import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location('publish_release', SCRIPTS / 'publish_release.py')
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)
sys.path.pop(0)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'NOTES.md').write_text('Release notes')

    def archive(self, platform, *, commit='a' * 40, unsafe=False, missing_manifest=False, rehearsal_only=False):
        name = f'noisefence-0.29.1-{platform}'
        elf = bytearray(20)
        elf[:6] = b'\x7fELF\x02\x01'
        elf[18:20] = release.PLATFORMS[platform].to_bytes(2, 'little')
        files = {'build.json': json.dumps({'project': 'NoiseFence', 'storage_schema': 7, 'version': '0.29.1', 'platform': platform,
                                         'commit': commit, 'rehearsal_only': rehearsal_only}).encode(),
                 'noisefence': bytes(elf), 'web/index.html': b'<html lang="en">Console</html>'}
        checks = ''.join(f'{hashlib.sha256(data).hexdigest()}  {path}\n' for path, data in files.items())
        files['SHA256SUMS'] = ('' if missing_manifest else checks).encode()
        archive = self.root / (name + '.tar.gz')
        with tarfile.open(archive, 'w:gz') as tar:
            for path, data in files.items():
                info = tarfile.TarInfo(f'{name}/{path}'); info.size = len(data)
                if path == 'noisefence': info.mode = 0o755
                tar.addfile(info, io.BytesIO(data))
            if unsafe:
                tar.addfile(tarfile.TarInfo('../escape'))
        (self.root / (archive.name + '.sha256')).write_text(f'{release.digest(archive)}  {archive.name}\n')

    def both(self):
        for platform in release.PLATFORMS:
            self.archive(platform)
        return release.validate_assets(self.root, 'v0.29.1', 'a' * 40)

    def test_both_architectures_provenance_and_internal_hashes(self):
        self.assertEqual(len(self.both()), 4)

    def test_refuse_wrong_commit_missing_manifest_and_traversal(self):
        self.both()
        for options in [{'commit': 'b' * 40}, {'unsafe': True}, {'missing_manifest': True}]:
            with self.subTest(options=options):
                self.archive('linux-arm64', **options)
                with self.assertRaises(ValueError):
                    release.validate_assets(self.root, 'v0.29.1', 'a' * 40)

    def test_host_rehearsal_and_invalid_markers_cannot_be_published(self):
        self.both()
        for value in [True, 'false', 1, None]:
            with self.subTest(value=value):
                self.archive('linux-arm64', rehearsal_only=value)
                with self.assertRaises(ValueError):
                    release.validate_assets(self.root, 'v0.29.1', 'a' * 40)

    def test_refuse_corrupt_or_missing_archive(self):
        assets = self.both()
        assets[0].write_bytes(b'corrupt')
        with self.assertRaises(ValueError):
            release.validate_assets(self.root, 'v0.29.1', 'a' * 40)
        assets[0].unlink()
        with self.assertRaises(FileNotFoundError):
            release.validate_assets(self.root, 'v0.29.1', 'a' * 40)

    @patch.object(release, 'verify_download')
    @patch.object(release, 'gh', return_value='[]')
    def test_publish_only_after_verified_upload(self, gh, verify):
        assets = self.both()
        release.publish('v0.29.1', self.root, assets, 'example/repo')
        calls = [c.args for c in gh.call_args_list]
        self.assertEqual([c[1] for c in calls], ['list', 'create', 'upload', 'edit'])
        self.assertIn('--draft', calls[1]); self.assertIn('--latest=true', calls[-1])
        verify.assert_called_once()
        gh.reset_mock(); verify.side_effect = ValueError('mismatch')
        with self.assertRaises(ValueError):
            release.publish('v0.29.1', self.root, assets, 'example/repo')
        self.assertNotIn('edit', [c.args[1] for c in gh.call_args_list])

    @patch.object(release, 'verify_download')
    @patch.object(release, 'gh')
    def test_rerun_preserves_published_and_resumes_draft(self, gh, verify):
        for draft in [False, True]:
            with self.subTest(draft=draft):
                gh.reset_mock()
                gh.return_value = json.dumps([{'tagName': 'v0.29.1', 'isDraft': draft}])
                release.publish('v0.29.1', self.root, [], 'example/repo')
                self.assertEqual([c.args[1] for c in gh.call_args_list],
                                 ['list', 'upload', 'edit'] if draft else ['list'])

    @patch.object(release, 'verify_download')
    @patch.object(release, 'gh', return_value='[]')
    def test_prerelease_does_not_replace_latest(self, gh, verify):
        release.publish('v0.29.1-rc.1', self.root, [], 'example/repo')
        self.assertIn('--prerelease=true', gh.call_args.args)
        self.assertIn('--latest=false', gh.call_args.args)

    def test_main_requires_both_provenances_before_publishing(self):
        self.both()
        argv=['publish_release.py','--tag','v0.29.1','--directory',str(self.root)]
        with patch.object(sys,'argv',argv),patch.dict(os.environ,{'GH_REPO':'crdffrance/NoiseFence'}), \
                patch.object(release,'cargo_version',return_value='0.29.1'), \
                patch.object(release.subprocess,'check_output',return_value='a'*40), \
                patch.object(release,'publish') as publish,patch.object(release,'verify_provenance') as verify:
            verify.side_effect=ValueError('untrusted source')
            with self.assertRaises(ValueError):release.main()
            publish.assert_not_called()
            verify.reset_mock();verify.side_effect=None
            release.main()
            self.assertEqual(verify.call_count,2);publish.assert_called_once()
            verify.reset_mock();publish.reset_mock();argv.append('--verify-only')
            release.main();verify.assert_not_called();publish.assert_not_called()

    @patch.object(release, 'gh', side_effect=RuntimeError('API unavailable'))
    def test_api_failure_does_not_create_release(self, gh):
        with self.assertRaises(RuntimeError):
            release.publish('v0.29.1', self.root, [], 'example/repo')
        self.assertEqual(gh.call_count, 1)
