"""Run the real shell installer against rebased temporary paths and no privileged utilities.

The candidate only records whether it was invoked. These tests prove rejection
ordering, not a successful systemd installation or a real release rehearsal.
"""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class InstallerPreflight(unittest.TestCase):
    def test_guard_runs_before_candidate_and_only_admits_known_local_state(self):
        for scenario in ('configured', 'selected', 'transport', 'history', 'replication_removed', 'old_candidate', 'fresh_selected', 'fresh_local', 'legacy_local', 'lost_installed_state', 'reserved', 'reserved_symlink', 'contended'):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                tools = root / 'tools'
                tools.mkdir()
                bundle = root / 'bundle'
                (bundle / 'deploy').mkdir(parents=True)
                (bundle / 'deploy/upgrade-check.py').write_bytes((ROOT / 'deploy/upgrade-check.py').read_bytes())
                (bundle / 'SHA256SUMS').write_text('')
                (bundle / 'build.json').write_text(json.dumps(dict(project='NoiseFence', version='0.31.9',
                    storage_schema=4 if scenario == 'old_candidate' else 7, commit='a' * 40, source_sha256='b' * 64)))
                data = root / 'data'
                data.mkdir()
                config = root / ('initial.toml' if scenario in ('fresh_selected', 'fresh_local') else 'etc/config.toml')
                config.parent.mkdir(exist_ok=True)
                configuration = f'data_dir={json.dumps(str(data))}\n'
                if scenario in ('configured', 'fresh_selected'):
                    configuration += '[management]\nbackend="postgresql"\n'
                elif scenario not in ('fresh_local', 'lost_installed_state'):
                    with contextlib.closing(sqlite3.connect(data / 'state.sqlite3')) as db, db:
                        db.executescript('CREATE TABLE cluster_state(key TEXT PRIMARY KEY,value TEXT);'
                                         'PRAGMA user_version=' + ('7' if scenario == 'selected' else '5'))
                        marker = {'transport': 'management_transport', 'history': 'runtime_history_protocol',
                                  'replication_removed': 'ha_required'}.get(scenario)
                        if marker:
                            db.execute('INSERT INTO cluster_state VALUES(?,?)', (marker, '1'))
                        if scenario == 'replication_removed':
                            db.execute('CREATE TABLE ha_local(message_id,generation,acked)')
                if scenario == 'lost_installed_state':
                    (root / 'opt').mkdir()
                    (root / 'opt/current').symlink_to('releases/missing')
                previous_opt = sorted((root / 'opt').glob('*'))
                config.write_text(configuration)
                before = config.read_bytes()
                candidate = bundle / 'noisefence'
                candidate.write_text('#!/bin/sh\necho "$1" > ' + str(root / 'candidate-invoked') + '\necho "noisefence 0.31.9"\n')
                candidate.chmod(0o700)
                # Only the documented absolute installation roots are rebased.
                source = (ROOT / 'deploy/install.sh').read_text()
                for old, new in [('/run/noisefence-upgrade.lock', root / 'upgrade.lock'), ('/var/lib/noisefence-upgrade', root / 'reservation'), ('/etc/noisefence', root / 'etc'), ('/opt/noisefence', root / 'opt'), ('/var/lib/noisefence', data)]:
                    source = source.replace(old, str(new))
                installer = root / 'install.sh'
                installer.write_text(source)
                (tools / 'python3').symlink_to(sys.executable)
                marker = root/'reservation/active.json'
                if scenario in ('reserved', 'reserved_symlink'):
                    marker.parent.mkdir()
                    if scenario == 'reserved':marker.write_text('deliberately unparsed reservation')
                    else:marker.symlink_to(root/'missing')
                for name, body in {'flock': f'#!{sys.executable}\nimport fcntl,sys\nfcntl.flock(int(sys.argv[2]),fcntl.LOCK_EX|fcntl.LOCK_NB)\n', 'id': '#!/bin/sh\necho 0\n', 'sha256sum': '#!/bin/sh\nexit 0\n',
                                   'realpath': f'#!{sys.executable}\nimport pathlib,sys\nprint(pathlib.Path(sys.argv[1]).resolve())\n'}.items():
                    path = tools / name
                    path.write_text(body)
                    path.chmod(0o700)
                args = ['/bin/sh', str(installer), str(bundle)]
                if scenario in ('fresh_selected', 'fresh_local'):
                    args.append(config.name)
                with (root/'upgrade.lock').open('a') as lock:
                    if scenario == 'contended':fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                    result = subprocess.run(args, cwd=root, env={'PATH': str(tools)}, capture_output=True, text=True, timeout=15)
                if scenario in ('fresh_local', 'legacy_local'):
                    # No privileged tools exist in PATH: a passing guard reaches
                    # only the synthetic --version invocation, then stops.
                    self.assertEqual((root / 'candidate-invoked').read_text().strip(), '--version')
                    self.assertNotIn('Local installation refused', result.stderr)
                    self.assertNotEqual(result.returncode, 0)
                else:
                    self.assertEqual(result.returncode, 1, result.stderr)
                    expected = ('durable upgrade reservation' if scenario.startswith('reserved') else
                                'Another host operation' if scenario == 'contended' else 'Local installation refused')
                    self.assertIn(expected, result.stderr)
                    self.assertFalse((root / 'candidate-invoked').exists())
                self.assertEqual(sorted((root / 'opt').glob('*')), previous_opt)
                self.assertEqual(config.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
