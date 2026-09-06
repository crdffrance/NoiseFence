import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location(
    'signature_sources', Path(__file__).resolve().parents[1] / 'deploy/fetch-unofficial-sigs.py')
fetcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetcher)


class SignatureSourceTests(unittest.TestCase):
    def test_all_sources_are_verified_before_directory_is_published(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            code, key = b'never execute this source', b'public test key'
            manifest = {'commit': 'a' * 40, 'files': {'script.sh': hashlib.sha256(code).hexdigest()},
                        'sanesecurity_key': {'url': 'https://example.test/key', 'sha256': hashlib.sha256(key).hexdigest()}}
            (root / 'unofficial-sigs.sources.json').write_text(json.dumps(manifest))
            destination = root / 'sources'

            def download(url):
                self.assertFalse(destination.exists())
                return key if url.endswith('/key') else code

            with patch.object(fetcher, 'ROOT', root):
                fetcher.fetch(destination, download)
                self.assertEqual((destination / 'script.sh').read_bytes(), code)
                self.assertEqual((destination / 'sanesecurity-publickey.gpg').read_bytes(), key)
                with self.assertRaisesRegex(ValueError, 'already exists'):
                    fetcher.fetch(destination, download)

    def test_corrupt_source_publishes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = {'commit': 'a' * 40, 'files': {'script.sh': '0' * 64},
                        'sanesecurity_key': {'url': 'https://example.test/key', 'sha256': '0' * 64}}
            (root / 'unofficial-sigs.sources.json').write_text(json.dumps(manifest))
            with patch.object(fetcher, 'ROOT', root):
                with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                    fetcher.fetch(root / 'sources', lambda _: b'corrupted')
            self.assertFalse((root / 'sources').exists())
            self.assertFalse(list(root.glob('.unofficial-*')))


if __name__ == '__main__':
    unittest.main()
