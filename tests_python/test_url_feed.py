import importlib.util
from pathlib import Path
import json
import unittest
spec=importlib.util.spec_from_file_location('url_feed',Path(__file__).resolve().parents[1]/'deploy/update-url-feed.py')
feed=importlib.util.module_from_spec(spec)
spec.loader.exec_module(feed)
class UrlFeedTests(unittest.TestCase):
    def test_import_is_data_only_deduplicated_and_preserves_tokens(self):
        result=json.loads(feed.convert(b'# comment\nhttps://example.com/a?token=abc\nhttps://example.com/a?token=abc\n',100))
        self.assertEqual(result,{'version':1,'updated':100,'urls':['https://example.com/a?token=abc']})
    def test_rejects_empty_malformed_and_oversize_feeds(self):
        for raw in (b'',b'javascript:alert(1)',b'https://example.com/\x00x',b'X'*(feed.LIMIT+1)):
            with self.assertRaises(ValueError):feed.convert(raw)
