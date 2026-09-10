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
        raise SystemExit('The OCR fixture cannot be combined with --attachments')
    profile = getattr(args, 'vision_fixture', 'image')
    if profile not in ('image', 'pdf', 'alternating', 'combined'):
        raise SystemExit('Unknown OCR fixture profile')
    if profile == 'alternating' and args.messages < 2:
        raise SystemExit('The alternating OCR profile requires at least two messages')
    with tempfile.TemporaryDirectory(prefix='nf-load-vision-') as temp:
        image, _ = fixtures.fixture(Path(temp))
        inputs = {'image': image.read_bytes()}
        if profile != 'image':
            inputs['pdf'] = (image.parent/'synthetic.pdf').read_bytes()
        sizes = set()
        expected_kinds = {}

        def fixture(index, _size, _html=False, _mailing=False):
            kind = ('image' if index % 2 == 0 else 'pdf') if profile == 'alternating' else profile
            message = EmailMessage(policy=SMTP)
            message['From'] = 'Synthetic <sender@example.test>'
            message['To'] = 'alice@example.test'
            message['Subject'] = 'Synthetic OCR capacity measurement'
            message['Message-ID'] = f'<load-{index}@example.test>'
            message['X-Load-ID'] = str(index)
            message['Date'] = 'Tue, 08 Sep 2026 08:00:00 +0000'
            message.set_content('Synthetic local image inspection. No external delivery.')
            for part_kind in (('image', 'pdf') if kind == 'combined' else (kind,)):
                maintype, subtype, filename = ('image', 'png', 'synthetic.png') if part_kind == 'image' else ('application', 'pdf', 'synthetic.pdf')
                message.add_attachment(inputs[part_kind], maintype=maintype, subtype=subtype, filename=filename)
            message.set_boundary('noisefence-public-vision-load')
            raw = message.as_bytes()
            sizes.add(len(raw))
            expected_kinds[load.digest(raw)] = kind
            return raw, load.digest(raw.split(b'\r\n\r\n', 1)[1])

        load.fixture = fixture
        args.message_bytes = len(fixture(0, 0)[0])
        root = args.output_dir.resolve()
        output_existed = root.exists()
        failure = None
        try:
            await original_run(args)
        except SystemExit as error:
            # A failed completeness requirement still leaves a valid report.
            # Preserve the OCR evidence, then preserve the original exit status.
            # Preflight failures must not read a stale output directory.
            if output_existed or error.code != 1 or not (root/'summary.json').is_file():
                raise
            report = json.loads((root/'summary.json').read_text())
            if not report.get('run_finished') or report.get('requirements_met') is not False:
                raise
            failure = error
        with sqlite3.connect(f'file:{root}/data/state.sqlite3?mode=ro', uri=True) as db:
            scans = [json.loads(row[0]) for row in db.execute('SELECT scan FROM messages')]
        completed = [s['vision'] for s in scans if s['vision']['status'] == 'complete']
        def verified(vision, kind):
            count = 2 if kind == 'combined' else 1
            return (kind != 'unknown' and vision['status'] == 'complete'
                    and vision['parts'] == count and vision['qr_codes'] == count
                    and vision['pages'] == count and vision['text_chars'] >= 80 * count)

        decoded = sum(verified(s['vision'], expected_kinds.get(s.get('raw_sha256'), 'unknown')) for s in scans)
        report = json.loads((root/'summary.json').read_text())
        report['fixture_profile'] = 'public-vision-worker-ocr-qr'
        report['vision_fixture'] = profile
        report['message_bytes_range'] = [min(sizes), max(sizes)]
        used_kinds = ('image', 'pdf') if profile == 'alternating' else (profile,)
        input_kinds = ('image', 'pdf') if profile in ('alternating', 'combined') else (profile,)
        report['fixture_inputs_sha256'] = {kind: load.digest(inputs[kind]) for kind in input_kinds}
        report['fixture_parts_per_message'] = {kind: 2 if kind == 'combined' else 1 for kind in used_kinds}
        if profile != 'pdf':
            report['fixture_image_sha256'] = load.digest(inputs['image'])
        by_kind = {}
        for kind in (*used_kinds, 'unknown'):
            observations = [s['vision'] for s in scans if expected_kinds.get(s.get('raw_sha256'), 'unknown') == kind]
            checked = [s for s in observations if verified(s, kind)]
            by_kind[kind] = {'messages': len(observations), 'complete': sum(s['status'] == 'complete' for s in observations),
                             'verified': len(checked), 'ocr_elapsed_ms': load.quantiles([s['elapsed_ms'] for s in observations])}
        report['ocr_by_kind'] = by_kind
        report['probe_sources_sha256'] = {str(p.relative_to(ROOT)): load.digest(p.read_bytes()) for p in (
            ROOT/'scripts/smtp_load.py', ROOT/'scripts/smtp_load_vision.py', ROOT/'tests/vision_worker.py')}
        report['ocr_verified_messages'] = decoded
        report['ocr_complete_messages'] = len(completed)
        report['ocr_requirements_met'] = bool(completed) and decoded == len(completed) and not by_kind['unknown']['messages']
        report['requirements_met'] = report.get('requirements_met', False) and report['ocr_requirements_met']
        report['ocr_elapsed_ms'] = load.quantiles([s['vision']['elapsed_ms'] for s in scans])
        report['ocr_backend_sha256'] = sorted({s['backend_sha256'] for s in completed})
        (root/'summary.json').write_text(json.dumps(report, indent=2)+'\n')
        print(json.dumps({'ocr_complete':len(completed),'ocr_verified':decoded,
                          'ocr_elapsed_ms':report['ocr_elapsed_ms']}), flush=True)
        if failure is not None:
            raise failure
        if not report['ocr_requirements_met']:
            raise SystemExit('A completed OCR did not decode the synthetic text and QR')


if __name__ == '__main__':
    load.run = run
    load.main(lambda parser: parser.add_argument('--vision-fixture', choices=('image', 'pdf', 'alternating', 'combined'),
        default='image', help='Public OCR fixture: image, PDF, alternating messages, or both attachments in each message'))
