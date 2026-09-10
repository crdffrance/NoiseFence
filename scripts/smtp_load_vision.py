#!/usr/bin/env python3
"""Extend the isolated SMTP load probe with the public synthetic OCR/QR fixture.

Run from the repository on Linux with Pillow, qrencode and DejaVu fonts installed.
Accepts smtp_load.py options; requires --vision-socket. No external mail or LLM.
"""
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
from email.message import EmailMessage
from email.policy import SMTP

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


load = module('smtp_load', ROOT/'scripts/smtp_load.py')
fixtures = module('vision_fixture', ROOT/'tests/vision_worker.py')
original_run = load.run


async def run(args):
    if not args.vision_socket:
        raise SystemExit('The OCR load profile requires --vision-socket')
    if getattr(args, 'attachments', False):
        raise SystemExit('The OCR image fixture cannot be combined with --attachments')
    with tempfile.TemporaryDirectory(prefix='nf-load-vision-') as temp:
        image, _ = fixtures.fixture(Path(temp))
        image_bytes = image.read_bytes()
        sizes = set()

        def fixture(index, _size, _html=False, _mailing=False):
            message = EmailMessage(policy=SMTP)
            message['From'] = 'Synthetic <sender@example.test>'
            message['To'] = 'alice@example.test'
            message['Subject'] = 'Synthetic OCR capacity measurement'
            message['Message-ID'] = f'<load-{index}@example.test>'
            message['X-Load-ID'] = str(index)
            message['Date'] = 'Tue, 08 Sep 2026 08:00:00 +0000'
            message.set_content('Synthetic local image inspection. No external delivery.')
            message.add_attachment(image_bytes, maintype='image', subtype='png', filename='synthetic.png')
            message.set_boundary('noisefence-public-vision-load')
            raw = message.as_bytes()
            sizes.add(len(raw))
            return raw, load.digest(raw.split(b'\r\n\r\n', 1)[1])

        load.fixture = fixture
        args.message_bytes = len(fixture(0, 0)[0])
        await original_run(args)
        root = args.output_dir.resolve()
        with sqlite3.connect(f'file:{root}/data/state.sqlite3?mode=ro', uri=True) as db:
            scans = [json.loads(row[0]) for row in db.execute('SELECT scan FROM messages')]
        completed = [s['vision'] for s in scans if s['vision']['status'] == 'complete']
        decoded = sum(s['qr_codes'] == 1 and s['pages'] == 1 and s['text_chars'] >= 80 for s in completed)
        report = json.loads((root/'summary.json').read_text())
        report['fixture_profile'] = 'public-vision-worker-ocr-qr'
        report['message_bytes_range'] = [min(sizes), max(sizes)]
        report['fixture_image_sha256'] = load.digest(image_bytes)
        report['probe_sources_sha256'] = {str(p.relative_to(ROOT)): load.digest(p.read_bytes()) for p in (
            ROOT/'scripts/smtp_load.py', ROOT/'scripts/smtp_load_vision.py', ROOT/'tests/vision_worker.py')}
        report['ocr_verified_messages'] = decoded
        report['ocr_complete_messages'] = len(completed)
        report['ocr_elapsed_ms'] = load.quantiles([s['vision']['elapsed_ms'] for s in scans])
        report['ocr_backend_sha256'] = sorted({s['backend_sha256'] for s in completed})
        (root/'summary.json').write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps({'ocr_complete':len(completed),'ocr_verified':decoded,
                          'ocr_elapsed_ms':report['ocr_elapsed_ms']}), flush=True)
        if not completed or decoded != len(completed):
            raise SystemExit('A completed OCR did not decode the synthetic text and QR')


if __name__ == '__main__':
    load.run = run
    load.main()
