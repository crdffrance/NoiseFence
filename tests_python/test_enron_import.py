"""Offline importer and train/holdout leakage regressions; synthetic emails only."""
import csv
from email.parser import BytesParser
from email.policy import default
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'research'))
from import_enron_csv import COLUMNS, import_archive
from merge_corpus import metadata, select_novel


class EnronImportTests(unittest.TestCase):
    def archive(self, root, rows, member='enron_spam_data.csv'):
        csvfile = io.StringIO(newline='')
        writer = csv.writer(csvfile)
        writer.writerow(COLUMNS)
        writer.writerows(rows)
        path = root / 'input.zip'
        with zipfile.ZipFile(path, 'w') as zipped:
            zipped.writestr(member, csvfile.getvalue())
        return path

    def test_labels_ids_dates_and_injected_headers_do_not_enter_mime(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = self.archive(root, [
                ['secret-id', 'Réunion\r\nX-Spam-Status: Yes', 'Bonjour,\0\ntexte été.', 'ham', '2000-01-01'],
                ['different-id', 'Réunion\r\nX-Spam-Status: Yes', 'Bonjour,\0\ntexte été.', 'ham', '2005-12-31'],
            ])
            report = import_archive(archive, root / 'import')
            rows = [json.loads(x) for x in (root / 'import/manifest.jsonl').read_text().splitlines()]
            self.assertEqual(len(rows), 1)
            raw = (root / 'import' / rows[0]['path']).read_bytes()
            msg = BytesParser(policy=default).parsebytes(raw)
            self.assertIsNone(msg['X-Spam-Status'])
            self.assertIsNone(msg['Date'])
            self.assertIsNone(msg['Message-ID'])
            self.assertIsNone(msg['From'])
            self.assertNotIn(b'secret-id', raw)
            self.assertEqual(msg.get_content().replace('\r\n', '\n'), 'Bonjour,\ntexte été.\n')
            self.assertEqual(report['counts']['exact_duplicate_rows_removed'], 1)
            self.assertEqual((root / 'import' / rows[0]['path']).stat().st_mode & 0o777, 0o600)
            with self.assertRaises(ValueError):
                import_archive(archive, root / 'import')
            self.assertEqual(raw, (root / 'import' / rows[0]['path']).read_bytes())

    def test_conflicts_are_removed_instead_of_first_label_winning(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = self.archive(root, [
                ['1', 'Same content', 'Expected meeting tomorrow.', 'ham', '2001'],
                ['2', 'Same content', 'Expected meeting tomorrow.', 'spam', '2001'],
            ])
            report = import_archive(archive, root / 'out')
            self.assertEqual(report['counts']['conflicting_exact_rows_removed'], 2)
            self.assertEqual((root / 'out/manifest.jsonl').read_text(), '')

    def test_invalid_label_and_zip_path_fail_before_publication(self):
        for label, member in [('unknown', 'enron_spam_data.csv'), ('ham', '../enron_spam_data.csv')]:
            with self.subTest(label=label, member=member), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                archive = self.archive(root, [['1', 'Subject', 'Body', label, '2001']], member)
                with self.assertRaises(ValueError):
                    import_archive(archive, root / 'out')
                self.assertFalse((root / 'out').exists())


class CampaignSeparationTests(unittest.TestCase):
    @staticmethod
    def row(n, simhash, spam=False, campaign=None):
        return {'raw_sha256': format(n, '064x'), 'campaign': campaign or format(n + 1000, '064x'),
                'simhash': format(simhash, '016x'), 'spam': spam}

    def test_transitive_near_duplicate_of_a_reserved_reference_is_excluded(self):
        rows = [self.row(1, 0), self.row(2, 0b111), self.row(3, 0b111111),
                self.row(4, 0xffffffffffffffff)]
        selected, counts = select_novel(rows, 1)
        self.assertEqual(set(selected), {2})
        self.assertEqual(counts['reference_overlap_rows_removed'], 2)

    def test_reserved_external_flag_cannot_be_cleared_by_augmentation(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'reserved.jsonl'
            row = {**self.row(1, 0), 'feature_version': 3, 'external_test': True}
            path.write_text(json.dumps(row) + '\n')
            self.assertEqual(len(metadata([path])), 1)
            with self.assertRaisesRegex(ValueError, 'Reserved external'):
                metadata([path], reject_external=True)

    def test_canonical_conflicts_and_duplicates_never_split(self):
        rows = [self.row(1, 0, False), self.row(2, 1, True),
                self.row(3, 0xffffffffffffffff, False), self.row(4, 0xffffffffffffffff, False)]
        selected, counts = select_novel(rows, 0)
        self.assertEqual(set(selected), {2})
        self.assertEqual(counts['novel_conflicting_rows_removed'], 2)
        self.assertEqual(counts['novel_duplicate_rows_removed'], 1)

    def test_spacing_normalization_also_blocks_transitive_reference_overlap(self):
        rows = [self.row(1, 0), self.row(2, 0xffffffffffffffff), self.row(3, 0xfffffffffffffffe)]
        rows[0].update(token_campaign='a' * 64, token_simhash='0000000000000000')
        rows[1].update(token_campaign='a' * 64, token_simhash='ffffffffffffffff')
        # Third row connects through the second, even though neither raw key
        # matches the held-out reference and its token key is absent.
        selected, counts = select_novel(rows, 1)
        self.assertEqual(selected, {})
        self.assertEqual(counts['reference_overlap_rows_removed'], 2)


if __name__ == '__main__':
    unittest.main()
