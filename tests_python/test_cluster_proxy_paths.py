"""Both cluster protocol versions must receive the bounded metadata allowance."""
from pathlib import Path
import fnmatch
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ClusterProxyPaths(unittest.TestCase):
    def test_nginx_routes_current_and_legacy_sync_outside_console_limit(self):
        config = (ROOT / 'deploy/nginx.conf').read_text()
        prefix, block = re.search(r'location \^~ (/api/v1/cluster/[^ ]*) \{([^}]+)', config).groups()
        for path in ('/api/v1/cluster/v1/sync', '/api/v1/cluster/v2/sync',
                     '/api/v1/cluster/v2/artifacts/digest'):
            self.assertTrue(path.startswith(prefix), path)
        self.assertFalse('/api/v1/login'.startswith(prefix))
        self.assertIn('client_max_body_size 4m;', block)
        self.assertIn('client_max_body_size 32k;', config)

    def test_caddy_excludes_both_protocols_from_console_body_limit(self):
        config = (ROOT / 'deploy/Caddyfile').read_text()
        cluster = re.search(r'@cluster path (\S+)', config)[1]
        excluded = re.search(r'@console not path (\S+)', config)[1]
        for path in ('/api/v1/cluster/v1/sync', '/api/v1/cluster/v2/sync'):
            self.assertTrue(fnmatch.fnmatchcase(path, cluster))
            self.assertTrue(fnmatch.fnmatchcase(path, excluded))
        self.assertFalse(fnmatch.fnmatchcase('/api/v1/login', cluster))


if __name__ == '__main__':
    unittest.main()
