import importlib.util
from pathlib import Path
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location('release_notes', SCRIPTS / 'release_notes.py')
release_notes = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release_notes)
sys.path.pop(0)


class ReleaseNotesTests(unittest.TestCase):
    def test_final_notes_exclude_unreleased_and_prerelease_history(self):
        changelog = ('# Changelog\n\n## [Unreleased]\n\nFuture\n\n'
                     '## [0.4.0] - 2026-09-09\n\nFinal\n\n### Migration\n\nSchema 2\n\n'
                     '## 0.4.0-dev.4 — Preview\n\nDevelopment\n')
        self.assertEqual(release_notes.notes_for(changelog, '0.4.0'),
                         'Final\n\n### Migration\n\nSchema 2\n')

    def test_plain_prerelease_heading(self):
        self.assertEqual(release_notes.notes_for('## 0.4.0-dev.4 — Preview\n\nFix\n',
                                                '0.4.0-dev.4'), 'Fix\n')

    def test_missing_empty_duplicate_and_prefix_matches_are_refused(self):
        for changelog in ['## [0.4.0-dev.4]\nPreview', '## 0.4.01\nOther',
                          '## [0.4.0]\n\n## [0.3.0]\nOlder',
                          '## [0.4.0]\nOne\n## 0.4.0\nTwo']:
            with self.subTest(changelog=changelog), self.assertRaises(ValueError):
                release_notes.notes_for(changelog, '0.4.0')
