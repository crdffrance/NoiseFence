#!/usr/bin/env python3
"""Real OCR on two template instances, with separate UIDs and namespaces.

Root-only Linux test using synthetic material and temporary, uniquely named units.
No production config, spool, worker socket or mailbox is used.
"""
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('vision_fixtures', ROOT/'tests/vision_worker.py')
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)


def run(*args):
    return subprocess.check_output(args, text=True, timeout=30).strip()


def call(path, request):
    raw = json.dumps(request).encode()
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(8)
        conn.connect(str(path))
        conn.sendall(struct.pack('!I', len(raw)) + raw)
        size = struct.unpack('!I', fixtures.worker.read_exact(conn, 4))[0]
        assert 0 < size <= fixtures.worker.MAX_RESPONSE
        return json.loads(fixtures.worker.read_exact(conn, size))


def main():
    assert os.geteuid() == 0 and Path('/run/systemd/system').exists()
    name = 'nf-vpool-' + uuid.uuid4().hex[:10]
    stage = Path('/srv')/name
    stage.mkdir(mode=0o755)
    worker = stage/'vision-worker.py'
    shutil.copy2(ROOT/'deploy/vision-worker.py', worker)
    worker.chmod(0o644)
    unit_dir = Path('/etc/systemd/system')
    services = [f'{name}@{i}.service' for i in (1, 2)]
    sockets = [f'{name}@{i}.socket' for i in (1, 2)]
    paths = [Path(f'/run/{name}-{i}/worker.sock') for i in (1, 2)]
    installed = []
    try:
        service = (ROOT/'deploy/noisefence-vision@.service').read_text().replace(
            'noisefence-vision@%i.socket', name+'@%i.socket').replace(
            'User=noisefence-vision-%i', 'User='+name+'-%i').replace(
            '/opt/noisefence/current/deploy/vision-worker.py', str(worker))
        socket_unit = (ROOT/'deploy/noisefence-vision@.socket').read_text().replace(
            '/run/noisefence-vision-%i/', '/run/'+name+'-%i/').replace(
            'SocketGroup=noisefence', 'SocketGroup=root')
        for suffix, content in [('service', service), ('socket', socket_unit)]:
            path = unit_dir/f'{name}@.{suffix}'
            with path.open('x') as handle:
                handle.write(content)
            installed.append(path)
        run('systemctl', 'daemon-reload')
        run('systemctl', 'start', *sockets, *services)
        pids = [int(run('systemctl', 'show', '-p', 'MainPID', '--value', s)) for s in services]
        assert all(pid > 0 for pid in pids)
        deadline = time.monotonic()+10
        while True:
            identities = []
            for pid in pids:
                fields = dict(line.split(':', 1) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line)
                identities.append((int(fields['Uid'].split()[0]), int(fields['Gid'].split()[0])))
            if all(uid > 0 for uid, _ in identities):
                break
            assert time.monotonic() < deadline, 'Worker credentials not applied'
            time.sleep(.02)
        assert identities[0][0] != identities[1][0] and all(uid > 0 for uid, _ in identities)
        assert all(len({os.readlink(f'/proc/{pid}/ns/{ns}') for pid in pids}) == 2 for ns in ('mnt', 'net'))
        # Create one synthetic sentinel in each instance's own /tmp. A helper
        # joins its mount namespace and drops all groups/UID; this checks file
        # and socket separation, not inherited seccomp filtering of that helper.
        for index, (pid, (uid, gid)) in enumerate(zip(pids, identities)):
            code = ('import os; from pathlib import Path; p=Path("/tmp/pool-sentinel");'
                    f'p.write_text("slot-{index}");os.chmod(p,0o600);os.chown(p,{uid},{gid})')
            run('nsenter', '--target', str(pid), '--mount', '/usr/bin/python3', '-c', code)
        for index, (pid, (uid, gid)) in enumerate(zip(pids, identities)):
            code = '''import os,socket,sys
from pathlib import Path
uid,gid,other,other_socket,expected=sys.argv[1:]
os.setgroups([]);os.setgid(int(gid));os.setuid(int(uid))
assert Path('/tmp/pool-sentinel').read_text()==expected
try: Path('/proc/'+other+'/root/tmp/pool-sentinel').read_bytes()
except (PermissionError,FileNotFoundError): pass
else: raise AssertionError('another instance tempdir is readable')
with socket.socket(socket.AF_UNIX) as conn:
 try: conn.connect(other_socket)
 except PermissionError: pass
 else: raise AssertionError('another instance socket is accessible')
print('isolated')
'''
            assert run('nsenter', '--target', str(pid), '--mount', '/usr/bin/python3', '-c', code,
                       str(uid), str(gid), str(pids[1-index]), str(paths[1-index]), f'slot-{index}') == 'isolated'
        backend = fixtures.worker.capabilities()['backend_sha256']
        with tempfile.TemporaryDirectory(prefix=name) as temp:
            image, payload = fixtures.fixture(Path(temp))
            image_request = fixtures.request(image)
            pdf_request = fixtures.request(Path(temp)/'synthetic.pdf', 'pdf')
            combined = fixtures.request(image)
            combined['parts'].extend(pdf_request['parts'])
            # Warm each exact worker and check backend identity before overlap.
            for path in paths:
                reply = call(path, image_request)
                assert reply['status'] == 'complete' and reply['backend_sha256'] == backend, reply
                assert len(reply['pages']) == 1
                assert 'NOISEFENCE' in reply['pages'][0]['text']
                assert payload in [c['data'] for c in reply['pages'][0]['codes']]
            barrier = threading.Barrier(3)
            def send(index):
                barrier.wait(timeout=5)
                return call(paths[index], combined)
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(send, i) for i in (0, 1)]
                barrier.wait(timeout=5)
                overlapping = False
                deadline = time.monotonic()+10
                while not all(f.done() for f in futures) and time.monotonic() < deadline:
                    active = [Path(f'/proc/{pid}/task/{pid}/children').read_text().strip() for pid in pids]
                    overlapping |= all(bool(children) for children in active)
                    time.sleep(.01)
                replies = [f.result(timeout=1) for f in futures]
            assert overlapping, 'No simultaneous job processes observed'
            for reply in replies:
                assert reply['status'] == 'complete' and reply['backend_sha256'] == backend, reply
                assert [(p['part'], p['page']) for p in reply['pages']] == [(0, 0), (1, 0)]
                for page in reply['pages']:
                    assert 'NOISEFENCE' in page['text']
                    assert payload in [c['data'] for c in page['codes']]
            print(json.dumps({'case':'isolated_pool_combined_attachments','workers':2,
                'distinct_users':True,'distinct_mount_and_network_namespaces':True,
                'cross_instance_file_and_socket_access_denied':True,'overlapping_jobs':True,
                'warmup_messages':2,'combined_messages':2,'pages_verified':6,
                'backend_sha256':backend,'scope':'real workers; not SMTP or throughput qualification'}), flush=True)
        assert all(run('systemctl', 'is-active', s) == 'active' for s in services)
    finally:
        subprocess.run(['systemctl', 'stop', *sockets, *services], check=False, timeout=30,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for path in installed:
            path.unlink()
        run('systemctl', 'daemon-reload')
        shutil.rmtree(stage)
        for path in paths:
            shutil.rmtree(path.parent, ignore_errors=True)


if __name__ == '__main__':
    main()
