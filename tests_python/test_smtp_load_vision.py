"""OCR report persistence on load failure; no claim of real OCR decoding here."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sqlite3
import tempfile
from email.parser import BytesParser
from email.policy import default
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('smtp_load_vision', ROOT/'scripts/smtp_load_vision.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class VisionReportTests(unittest.IsolatedAsyncioTestCase):
    async def exercise(self, complete=True, qr=1, preflight=False, profile='image', unknown=False):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)/'run'
            count = 3 if profile == 'alternating' else 1
            args = SimpleNamespace(vision_socket='/synthetic-unused.sock', output_dir=root,
                                   vision_fixture=profile, messages=count)

            def image_fixture(directory):
                image = directory/'synthetic.png'
                image.write_bytes(b'Synthetic fixture bytes, never decoded in this unit test')
                (directory/'synthetic.pdf').write_bytes(b'%PDF-Synthetic unit fixture, never decoded')
                return image, 'https://example.invalid/'

            async def fake_run(_args):
                if preflight:
                    raise SystemExit('preflight failed')
                (root/'data').mkdir(parents=True)
                # Check that the wrapper supplies the callback expected by smtp_load.
                with sqlite3.connect(root/'data/state.sqlite3') as db:
                    db.execute('CREATE TABLE messages(scan TEXT)')
                    # Reverse storage order: attribution must use the original
                    # message digest, not SQLite row order or alternating rows.
                    for index in reversed(range(count)):
                        raw, digest = probe.load.fixture(index, 100, False, False)
                        self.assertEqual(probe.load.digest(raw.split(b'\r\n\r\n', 1)[1]), digest)
                        kind = ('image' if index % 2 == 0 else 'pdf') if profile == 'alternating' else profile
                        parsed = BytesParser(policy=default).parsebytes(raw)
                        attachments = list(parsed.iter_attachments())
                        self.assertEqual(len(attachments), 1)
                        self.assertEqual(attachments[0].get_content_type(), 'image/png' if kind == 'image' else 'application/pdf')
                        self.assertEqual(attachments[0].get_payload(decode=True),
                            b'Synthetic fixture bytes, never decoded in this unit test' if kind == 'image'
                            else b'%PDF-Synthetic unit fixture, never decoded')
                        db.execute('INSERT INTO messages VALUES (?)', (json.dumps({
                            'raw_sha256': '0'*64 if unknown else probe.load.digest(raw), 'vision': {
                            'status': 'complete', 'qr_codes': qr, 'pages': 1, 'text_chars': 124,
                            'elapsed_ms': 42 if kind == 'image' else 84, 'backend_sha256': 'a'*64}}),))
                (root/'summary.json').write_text(json.dumps({
                    'run_finished': True, 'requirements_met': complete, 'complete': int(complete),
                    'statuses': {'content_inspection': {'complete' if complete else 'incomplete': 1}}}))
                if not complete:
                    raise SystemExit(1)

            failure = None
            with patch.object(probe.fixtures, 'fixture', image_fixture), \
                    patch.object(probe, 'original_run', fake_run), \
                    patch.object(probe.load, 'fixture'), contextlib.redirect_stdout(io.StringIO()):
                try:
                    await probe.run(args)
                except SystemExit as error:
                    failure = error.code
            report = json.loads((root/'summary.json').read_text()) if root.exists() else None
            return failure, report

    async def test_success_records_verified_ocr(self):
        failure, report = await self.exercise()
        self.assertIsNone(failure)
        self.assertTrue(report['requirements_met'])
        self.assertEqual(report['ocr_verified_messages'], 1)
        self.assertEqual(report['ocr_elapsed_ms']['p95'], 42)

    async def test_incomplete_other_filter_preserves_ocr_evidence_and_failure(self):
        failure, report = await self.exercise(complete=False)
        self.assertEqual(failure, 1)
        self.assertFalse(report['requirements_met'])
        self.assertEqual(report['complete'], 0)
        self.assertEqual(report['ocr_verified_messages'], 1)
        self.assertEqual(report['statuses']['content_inspection'], {'incomplete': 1})

    async def test_wrong_qr_still_fails_with_evidence(self):
        failure, report = await self.exercise(qr=0)
        self.assertIsInstance(failure, str)
        self.assertEqual(report['ocr_verified_messages'], 0)
        self.assertFalse(report['requirements_met'])
        self.assertFalse(report['ocr_requirements_met'])

    async def test_preflight_failure_does_not_create_report(self):
        failure, report = await self.exercise(preflight=True)
        self.assertEqual(failure, 'preflight failed')
        self.assertIsNone(report)

    async def test_pdf_is_mime_encoded_and_attributed_to_pdf(self):
        failure, report = await self.exercise(profile='pdf')
        self.assertIsNone(failure)
        self.assertEqual(report['vision_fixture'], 'pdf')
        self.assertEqual(set(report['fixture_inputs_sha256']), {'pdf'})
        self.assertNotIn('fixture_image_sha256', report)
        self.assertEqual(report['ocr_by_kind']['pdf']['verified'], 1)
        self.assertEqual(report['ocr_elapsed_ms']['p95'], 84)

    async def test_alternating_keeps_latency_and_coverage_separate_in_any_database_order(self):
        failure, report = await self.exercise(profile='alternating')
        self.assertIsNone(failure)
        self.assertEqual(report['ocr_by_kind']['image']['messages'], 2)
        self.assertEqual(report['ocr_by_kind']['pdf']['messages'], 1)
        self.assertEqual(report['ocr_by_kind']['image']['ocr_elapsed_ms']['p95'], 42)
        self.assertEqual(report['ocr_by_kind']['pdf']['ocr_elapsed_ms']['p95'], 84)
        self.assertEqual(report['ocr_by_kind']['unknown']['messages'], 0)
        self.assertEqual(report['ocr_verified_messages'], 3)

    async def test_unknown_original_digest_cannot_pass_pdf_coverage(self):
        failure, report = await self.exercise(profile='pdf', unknown=True)
        self.assertIsInstance(failure, str)
        self.assertFalse(report['requirements_met'])
        self.assertFalse(report['ocr_requirements_met'])
        self.assertEqual(report['ocr_by_kind']['unknown']['messages'], 1)

    async def test_alternating_incomplete_filter_retains_each_kind_and_original_failure(self):
        failure, report = await self.exercise(profile='alternating', complete=False)
        self.assertEqual(failure, 1)
        self.assertFalse(report['requirements_met'])
        self.assertEqual(report['ocr_by_kind']['image']['verified'], 2)
        self.assertEqual(report['ocr_by_kind']['pdf']['verified'], 1)


if __name__ == '__main__':
    unittest.main()
