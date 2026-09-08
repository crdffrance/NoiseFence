#!/usr/bin/env python3
"""Bounded SMTP load against a private daemon and loopback sink; synthetic mail only."""
import argparse
import asyncio
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import signal
import socket
import sqlite3
import subprocess
import time


def digest(data):
    return hashlib.sha256(data).hexdigest()


def quantiles(values):
    import math
    ordered = sorted(values)
    return {key: round(ordered[max(0, math.ceil(len(ordered)*fraction)-1)], 3)
            if ordered else None for key, fraction in [('p50', .5), ('p95', .95), ('max', 1)]}


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def fixture(index, size, html=False):
    header = (f'From: Synthetic <sender@example.test>\r\nTo: alice@example.test\r\n'
              f'Subject: Reunion de travail {index}\r\n'
              f'Message-ID: <load-{index}@example.test>\r\nX-Load-ID: {index}\r\n'
              'Date: Tue, 08 Sep 2026 08:00:00 +0000\r\n'
              'MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n').encode()
    if html:
        header=header.replace(b'Content-Type: text/plain',b'Content-Type: text/html')
    # Include dot transparency, many small writes, and a deterministic body.
    line = b'Bonjour, le rendez-vous de travail est confirme pour demain.\r\n'
    if html:
        line=b'<p>Reunion de travail <a href="https://example.com/calendar">https://example.com</a></p>\r\n'
    body = b'.Ligne commencant par un point.\r\n'
    remaining = max(0, size-len(header)-len(body)-2)
    body += line*(remaining//len(line)) + b'x'*(remaining % len(line)) + b'\r\n'
    return header + body, digest(body)


async def response(reader):
    while True:
        line = await asyncio.wait_for(reader.readline(), 15)
        if len(line) < 6 or not line[:3].isdigit():
            raise RuntimeError('Invalid or truncated SMTP response')
        if line[3:4] == b' ':
            return int(line[:3]), line.decode().strip()


async def command(reader, writer, text):
    writer.write(text.encode())
    await writer.drain()
    return await response(reader)


async def run(args):
    root = args.output_dir.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    binary = args.binary.resolve(strict=True)
    received, accepted, latencies, errors = [], {}, [], []
    retries = Counter()
    sink_tasks = set()
    started = time.monotonic()
    peak_rss = peak_threads = peak_pending = 0
    cpu_seconds = 0.0
    child = None
    monitor_task = None
    log = None
    report = {'run_finished': False, 'schema': 'noisefence-smtp-load-1',
              'binary_sha256': digest(binary.read_bytes()),
              'version': subprocess.check_output([str(binary), '--version'], text=True).strip(),
              'machine': {'system': platform.platform(), 'cpu_count': os.cpu_count()},
              'messages': args.messages, 'concurrency': args.concurrency,
              'message_bytes': args.message_bytes, 'processing': args.processing,
              'relay_workers': args.relay_workers, 'retry_policy': 'bounded exponential jitter, max 2 seconds',
              'transport': 'loopback plaintext both hops', 'durability': 'unmodified SQLite FULL + spool fsync',
              'exclusions': ['DNS/authentication', 'DQS', 'LLM', 'Proton', 'TLS', 'traffic representativeness'],
              'components': {'semantic': bool(args.semantic_encoder),
                             'semantic_parallel': args.semantic_parallel, 'semantic_timeout_ms': args.semantic_timeout_ms,
                             'antivirus': bool(args.antivirus_socket), 'signatures': bool(args.signatures_socket),
                             'vision': bool(args.vision_socket), 'protection': getattr(args, 'protection', False), 'html_fixture':getattr(args,'html',False)},
              'cpu_environment': {k: os.environ.get(k) for k in ('RAYON_NUM_THREADS', 'CANDLE_NUM_THREADS', 'TOKENIZERS_PARALLELISM', 'TOKIO_WORKER_THREADS')}}
    for name in ('lexical_model', 'semantic_combination'):
        value = getattr(args, name)
        report[name+'_sha256'] = digest(value.read_bytes()) if value else None

    async def sink(reader, writer):
        sink_tasks.add(asyncio.current_task())
        try:
            writer.write(b'220 sink.example.test ESMTP\r\n')
            await writer.drain()
            while True:
                line = await asyncio.wait_for(reader.readline(), 15)
                if not line:
                    break
                if line.startswith(b'EHLO '):
                    writer.write(b'250-sink.example.test\r\n250-8BITMIME\r\n250 SIZE 30000000\r\n')
                elif line.startswith((b'MAIL FROM:', b'RCPT TO:')):
                    writer.write(b'250 OK\r\n')
                elif line == b'DATA\r\n':
                    writer.write(b'354 Send data\r\n')
                    await writer.drain()
                    chunks = []
                    total = 0
                    while True:
                        line = await asyncio.wait_for(reader.readline(), 15)
                        if not line:
                            raise RuntimeError('Sink truncated DATA')
                        if line == b'.\r\n':
                            break
                        line = line[1:] if line.startswith(b'..') else line
                        total += len(line)
                        if total > 2*1024*1024:
                            raise RuntimeError('Sink size bound')
                        chunks.append(line)
                    raw = b''.join(chunks)
                    headers, body = raw.split(b'\r\n\r\n', 1)
                    ids = [int(h.split(b':', 1)[1]) for h in headers.split(b'\r\n') if h.lower().startswith(b'x-load-id:')]
                    if len(ids) != 1:
                        raise RuntimeError('Missing/duplicate synthetic message identifier')
                    received.append((ids[0], digest(body), time.monotonic()))
                    writer.write(b'250 Delivered locally\r\n')
                elif line == b'QUIT\r\n':
                    writer.write(b'221 Bye\r\n')
                    await writer.drain()
                    break
                else:
                    raise RuntimeError('Unexpected sink command')
                await writer.drain()
        except Exception as exc:
            errors.append(type(exc).__name__ + ': ' + str(exc))
        finally:
            writer.close()
            await writer.wait_closed()
            sink_tasks.discard(asyncio.current_task())

    listener = await asyncio.start_server(sink, '127.0.0.1', 0)
    sink_port = listener.sockets[0].getsockname()[1]
    smtp_port, web_port = port(), port()
    while web_port == smtp_port:
        web_port = port()
    quote = lambda value: json.dumps(str(value))
    config = (f'hostname="gateway.example.test"\ndata_dir={quote(root / "data")}\n'
              f'[smtp]\nlisten="127.0.0.1:{smtp_port}"\nminimum_free_bytes=104857600\n'
              f'max_connections=256\nmax_connections_per_ip=256\nmax_message_bytes=2097152\n')
    if args.processing is not None:
        config += f'max_processing={args.processing}\n'
    config += (f'[web]\nlisten="127.0.0.1:{web_port}"\npublic_origin="http://127.0.0.1:3000"\n'
               f'static_dir={quote(root)}\nsecure_cookies=false\n'
               '[filter]\nmode="observe"\nauthentication=false\nmax_analysis_bytes=2097152\n')
    if args.lexical_model:
        config += f'model={quote(args.lexical_model.resolve())}\n'
    if args.semantic_encoder:
        config += (f'[filter.semantic]\nencoder_dir={quote(args.semantic_encoder.resolve())}\n'
                   f'combination={quote(args.semantic_combination.resolve())}\n'
                   f'max_parallel={args.semantic_parallel}\ntimeout_ms={args.semantic_timeout_ms}\n')
    for name in ('antivirus', 'signatures', 'vision'):
        value = getattr(args, name+'_socket')
        if value:
            config += f'[{name}]\nsocket={quote(value.resolve())}\ntimeout_ms=3000\n'
    config += (f'[relay]\nworkers={args.relay_workers}\nrequire_tls=false\nallow_loopback_plaintext=true\n'
               f'port={sink_port}\npostmaster="alice@example.test"\n'
               '[[domains]]\nname="example.test"\nnext_hops=["127.0.0.1"]\nrecipients=["alice@example.test"]\n')
    if getattr(args,'protection',False):
        config += '[protection]\n'
    cfg = root/'config.toml'
    cfg.write_text(config)
    report['config_sha256'] = digest(config.encode())

    async def monitor():
        nonlocal peak_rss, peak_threads, peak_pending, cpu_seconds
        while True:
            proc = Path(f'/proc/{child.pid}')
            try:
                fields = dict(line.split(':', 1) for line in (proc/'status').read_text().splitlines() if ':' in line)
                peak_rss = max(peak_rss, int(fields.get('VmRSS', '0').split()[0])*1024)
                peak_threads = max(peak_threads, int(fields.get('Threads', '0')))
                stat = (proc/'stat').read_text().rsplit(')', 1)[1].split()
                cpu_seconds = (int(stat[11])+int(stat[12]))/os.sysconf('SC_CLK_TCK')
            except (OSError, ValueError):
                pass
            try:
                with sqlite3.connect(f'file:{root}/data/state.sqlite3?mode=ro', uri=True, timeout=.1) as db:
                    pending = db.execute("SELECT COUNT(*) FROM deliveries WHERE status IN ('pending','sending')").fetchone()[0]
                    peak_pending = max(peak_pending, pending)
            except sqlite3.Error:
                pass
            await asyncio.sleep(.1)

    async def sender(index):
        raw, body_hash = fixture(index, args.message_bytes, getattr(args,"html",False))
        # SMTP dot-stuffing only; the receiver must preserve all original body bytes.
        wire = raw.replace(b'\r\n.', b'\r\n..') + b'.\r\n'
        began = time.monotonic()
        attempt = 0
        rng = random.Random(index)
        while True:
            reader, writer = await asyncio.open_connection('127.0.0.1', smtp_port)
            try:
                code, _ = await response(reader)
                if code == 220:
                    for text in ('EHLO sender.example.test\r\n', 'MAIL FROM:<sender@example.test>\r\n', 'RCPT TO:<alice@example.test>\r\n'):
                        code, _ = await command(reader, writer, text)
                        if code != 250:
                            raise RuntimeError(f'Envelope response {code}')
                    code, _ = await command(reader, writer, 'DATA\r\n')
                    if code == 354:
                        writer.write(wire)
                        await writer.drain()
                        code, text = await response(reader)
                        if code != 250:
                            # No retry after DATA: record uncertainty instead of hiding duplicates.
                            raise RuntimeError(f'Post-DATA response {code}')
                        accepted[index] = {'queue_id': text.rsplit(' ', 1)[-1], 'body_sha256': body_hash}
                        latencies.append((time.monotonic()-began)*1000)
                        return
                if code not in (421, 451, 452):
                    raise RuntimeError(f'Unexpected pre-DATA response {code}')
                retries[str(code)] += 1
            finally:
                writer.close()
                await writer.wait_closed()
            attempt += 1
            await asyncio.sleep(min(2, .025*2**min(attempt, 6))*(.5+rng.random()))

    try:
        log = (root/'daemon.log').open('wb')
        child = subprocess.Popen([str(binary), '--config', str(cfg), 'serve'], stdout=log, stderr=log,
                                 start_new_session=True, env={**os.environ, 'RUST_LOG': 'noisefence=info'})
        monitor_task = asyncio.create_task(monitor())
        for _ in range(600):
            if child.poll() is not None:
                raise RuntimeError('Daemon exited; see daemon.log')
            try:
                reader, writer = await asyncio.open_connection('127.0.0.1', smtp_port)
                await response(reader)
                writer.close()
                await writer.wait_closed()
                break
            except ConnectionRefusedError:
                await asyncio.sleep(.1)
        else:
            raise RuntimeError('Daemon startup timeout')
        workload_start = time.monotonic()
        queue = asyncio.Queue()
        for index in range(args.messages):
            queue.put_nowait(index)

        async def producer():
            while not queue.empty():
                await sender(queue.get_nowait())

        await asyncio.wait_for(asyncio.gather(*(producer() for _ in range(args.concurrency))), 180)
        admission_end = time.monotonic()
        for _ in range(1800):
            with sqlite3.connect(f'file:{root}/data/state.sqlite3?mode=ro', uri=True) as db:
                counts = dict(db.execute('SELECT status,COUNT(*) FROM deliveries GROUP BY status'))
            if counts.get('delivered', 0) == args.messages:
                break
            if child.poll() is not None:
                raise RuntimeError('Daemon exited during drain')
            await asyncio.sleep(.1)
        else:
            raise RuntimeError('Queue did not drain within 180 seconds')
        drained = time.monotonic()
        with sqlite3.connect(f'file:{root}/data/state.sqlite3?mode=ro', uri=True) as db:
            scans = [(key, json.loads(raw)) for key, raw in db.execute('SELECT id,scan FROM messages')]
            integrity = db.execute('PRAGMA integrity_check').fetchone()[0]
        received_counts = Counter(index for index, _, _ in received)
        missing = sorted(set(accepted) - set(received_counts))
        extra = sorted(set(received_counts) - set(accepted))
        duplicates = sum(max(0, n-1) for n in received_counts.values())
        changed_bodies = sum(accepted.get(i, {}).get('body_sha256') != body for i, body, _ in received)
        statuses = {component: dict(Counter(scan.get(component, {}).get('status', 'absent') for _, scan in scans))
                    for component in ('semantic', 'antivirus', 'signatures', 'vision', 'llm')}
        complete = sum(scan['complete'] for _, scan in scans)
        checks = (len(accepted) == args.messages == len(scans) == len(received) and not missing and not extra
                  and not duplicates and not changed_bodies and not errors and integrity == 'ok'
                  and {key for key, _ in scans} == {value['queue_id'] for value in accepted.values()})
        report.update(run_finished=True, correctness_passed=checks, accepted=len(accepted), delivered=len(received),
                      complete=complete, incomplete=len(scans)-complete, statuses=statuses,
                      missing=len(missing), extra=len(extra), duplicates=duplicates, changed_bodies=changed_bodies,
                      retryable_responses=dict(retries), acceptance_ms=quantiles(latencies),
                      analysis_ms=quantiles([scan['elapsed_ms'] for _, scan in scans]),
                      admission_seconds=round(admission_end-workload_start, 3),
                      drained_seconds=round(drained-workload_start, 3),
                      accepted_per_second=round(len(accepted)/(admission_end-workload_start), 3),
                      delivered_per_second=round(len(received)/(drained-workload_start), 3),
                      complete_per_second=round(complete/(drained-workload_start), 3),
                      delivery_states=counts, integrity=integrity)
    except Exception as exc:
        report['error'] = type(exc).__name__ + ': ' + str(exc)
    finally:
        if monitor_task:
            monitor_task.cancel()
            await asyncio.gather(monitor_task, return_exceptions=True)
        if child and child.poll() is None:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                await asyncio.wait_for(asyncio.to_thread(child.wait), 40)
            except TimeoutError:
                os.killpg(child.pid, signal.SIGKILL)
                await asyncio.to_thread(child.wait)
        listener.close()
        await listener.wait_closed()
        for task in list(sink_tasks):
            task.cancel()
        await asyncio.gather(*list(sink_tasks), return_exceptions=True)
        if log:
            log.close()
        report.update(peak_daemon_rss_bytes=peak_rss or None, peak_daemon_threads=peak_threads or None,
                      peak_pending_deliveries=peak_pending, daemon_cpu_seconds=cpu_seconds or None,
                      wall_seconds=round(time.monotonic()-started, 3), sink_errors=errors)
        (root/'summary.json').write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps(report, indent=2), flush=True)
    if not report.get('correctness_passed'):
        raise SystemExit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--output-dir', type=Path, required=True, help='New private directory; never an existing spool')
    parser.add_argument('--messages', type=int, default=200)
    parser.add_argument('--concurrency', type=int, default=8)
    parser.add_argument('--message-bytes', type=int, default=1024)
    parser.add_argument('--processing', type=int, default=None, help='Omit to measure releases before this option existed')
    parser.add_argument('--relay-workers', type=int, default=8)
    for name in ('lexical-model', 'semantic-encoder', 'semantic-combination', 'antivirus-socket', 'signatures-socket', 'vision-socket'):
        parser.add_argument('--'+name, type=Path)
    parser.add_argument('--protection',action='store_true',help='Enable local advisory protection; no provider calls')
    parser.add_argument('--html',action='store_true',help='Use synthetic HTML links for parser load')
    parser.add_argument('--semantic-parallel', type=int, default=1)
    parser.add_argument('--semantic-timeout-ms', type=int, default=500)
    args = parser.parse_args()
    if not (1 <= args.messages <= 5000 and 1 <= args.concurrency <= 128 and 512 <= args.message_bytes <= 1048576
            and 1 <= args.relay_workers <= 64 and (args.processing is None or 1 <= args.processing <= 64)):
        parser.error('Load outside bounds: 1..5000 messages, 1..128 clients, 512B..1MiB, 1..64 workers')
    if bool(args.semantic_encoder) != bool(args.semantic_combination) or (args.semantic_encoder and not args.lexical_model):
        parser.error('Semantic measurement needs encoder, combination and lexical model')
    os.umask(0o077)
    asyncio.run(run(args))


if __name__ == '__main__':
    main()
