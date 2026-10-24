"""Adversarial archives and exact-identity provenance, with no live publication."""
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'deploy/postgresql'))
import release_bundle as bundle
import upgrade_stage as stage
import upgrade_reservation as reservation
sys.path.pop(0)

VERSION = '0.31.9'
COMMIT = 'a'*40
PLATFORM = 'linux-arm64'
TOP = f'noisefence-{VERSION}-{PLATFORM}'


def fixture(path, *, extra=(), change=None, pax=None, tail=b'', binary_mode=0o755):
    elf = bytearray(32); elf[:6] = b'\x7fELF\x02\x01'; elf[18:20] = (183).to_bytes(2, 'little')
    files = {'noisefence': bytes(elf),
             'build.json': json.dumps({'project': 'NoiseFence', 'storage_schema': 7,
                 'version': VERSION, 'platform': PLATFORM, 'commit': COMMIT}).encode(),
             'web/index.html': b'<html>synthetic console</html>',
             'deploy/never-run.sh': b'#!/bin/sh\nexit 1\n'}
    if change: change(files)
    files['SHA256SUMS'] = ''.join(f'{hashlib.sha256(v).hexdigest()}  {k}\n' for k,v in files.items()).encode()
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode='w', format=tarfile.PAX_FORMAT) as tar:
        for name, value in files.items():
            member = tarfile.TarInfo(TOP+'/'+name); member.size = len(value)
            member.mode = binary_mode if name == 'noisefence' else 0o644
            if pax: member.pax_headers = pax
            tar.addfile(member, io.BytesIO(value))
        for member, value in extra: tar.addfile(member, io.BytesIO(value))
    path.write_bytes(gzip.compress(raw.getvalue()+tail))
    return files


class BundleTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve(); self.path = self.root/'candidate.tar.gz'
        self.files = fixture(self.path)

    def inspect(self, **kw):
        return bundle.inspect_archive(self.path, VERSION, PLATFORM, COMMIT, **kw)

    def test_complete_archive_extracts_exact_files_without_running_any(self):
        destination = self.root/'new'
        result = self.inspect(destination=destination)
        self.assertEqual(result['files'], {k:hashlib.sha256(v).hexdigest() for k,v in self.files.items()})
        self.assertEqual((destination/'noisefence').stat().st_mode & 0o777, 0o755)
        self.assertEqual((destination/'deploy/never-run.sh').read_bytes(), self.files['deploy/never-run.sh'])
        with self.assertRaises(FileExistsError): self.inspect(destination=destination)

    def test_rejects_foreign_release_and_bad_elf(self):
        for version, platform, commit in [('0.31.8',PLATFORM,COMMIT),(VERSION,'linux-amd64',COMMIT),(VERSION,PLATFORM,'b'*40)]:
            with self.assertRaises(ValueError): bundle.inspect_archive(self.path,version,platform,commit)
        fixture(self.path, change=lambda d:d.update(noisefence=b'\x7fELF'+b'\x00'*28))
        with self.assertRaisesRegex(ValueError,'64-bit'): self.inspect()

    def test_rejects_unsafe_duplicate_links_and_devices(self):
        for name, kind in [('../escape',tarfile.REGTYPE),('/escape',tarfile.REGTYPE),
                (TOP+'/../escape',tarfile.REGTYPE),(TOP+'/web/./x',tarfile.REGTYPE),
                (TOP+'/noisefence',tarfile.REGTYPE),(TOP+'/link',tarfile.SYMTYPE),
                (TOP+'/hardlink',tarfile.LNKTYPE),(TOP+'/device',tarfile.CHRTYPE),
                (TOP+'/fifo',tarfile.FIFOTYPE),(TOP+'/sparse',tarfile.GNUTYPE_SPARSE),
                (TOP+'/gnu-name',tarfile.GNUTYPE_LONGNAME)]:
            with self.subTest(name=name,kind=kind):
                member=tarfile.TarInfo(name);member.type=kind;member.linkname='/etc/passwd'
                fixture(self.path,extra=[(member,b'')])
                with self.assertRaises(ValueError): self.inspect()

    def test_rejects_file_parent_conflict_in_both_orders(self):
        for files in [{'a':b'x','a/b':b'y'},{'a/b':b'y','a':b'x'}]:
            fixture(self.path,change=lambda d:d.update(files))
            with self.assertRaises(ValueError): self.inspect()

    def test_rejects_duplicate_json_and_inconsistent_manifests(self):
        fixture(self.path,change=lambda d:d.update({'build.json':b'{"project":"NoiseFence","project":"other"}'}))
        with self.assertRaisesRegex(ValueError,'Duplicate'): self.inspect()
        fixture(self.path,change=lambda d:d.update({'SHA256SUMS':b'not the final manifest'}))
        # The fixture's manifest names itself, which must never be accepted.
        with self.assertRaisesRegex(ValueError,'checksums'): self.inspect()

    def test_empty_console_and_non_executable_binary_are_refused(self):
        fixture(self.path,change=lambda d:d.update({'web/index.html':b''}))
        with self.assertRaisesRegex(ValueError,'empty'):self.inspect()
        fixture(self.path,binary_mode=0o644)
        with self.assertRaisesRegex(ValueError,'not executable'):self.inspect()

    def test_caps_files_compression_expansion_and_metadata(self):
        with patch.object(bundle,'MAX_ARCHIVE',1):
            with self.assertRaises(ValueError): self.inspect()
        with patch.object(bundle,'MAX_MEMBERS',2):
            with self.assertRaises(ValueError): self.inspect()
        with patch.object(bundle,'MAX_EXPANDED',1):
            with self.assertRaises(ValueError): self.inspect()
        fixture(self.path,change=lambda d:d.update({'build.json':b' '* (bundle.MAX_METADATA+1)}))
        with self.assertRaisesRegex(ValueError,'metadata'): self.inspect()

    def test_bounded_pax_support_rejects_sparse_extensions(self):
        fixture(self.path,pax={'mtime':'1234567890.123456'})
        self.inspect()
        for pax in [{'GNU.sparse.map':'0,999999999'}, {'xattr.user.data':'x'}, {'mtime':'nan'}]:
            fixture(self.path,pax=pax)
            with self.assertRaises(ValueError): self.inspect()
        fixture(self.path,pax={'path':'x'*20000})
        with self.assertRaisesRegex(ValueError,'PAX header'): self.inspect()

    def test_rejects_data_after_tar_end_and_truncated_gzip(self):
        fixture(self.path,tail=b'unlisted payload')
        with self.assertRaisesRegex(ValueError,'after the tar'): self.inspect()
        fixture(self.path);self.path.write_bytes(self.path.read_bytes()[:-5])
        with self.assertRaises((EOFError,ValueError,tarfile.TarError)): self.inspect()

    def test_verifier_binds_repo_workflow_tag_source_and_hosted_runner(self):
        answer=b'[{"verificationResult":{"statement":{}}}]'
        with patch.object(bundle,'bounded_command',return_value=answer) as run:
            receipt=bundle.verify_provenance(self.path,VERSION,COMMIT)
        args=run.call_args.args[0]
        for flag,value in [('--repo',bundle.REPOSITORY),('--hostname','github.com'),
                           ('--signer-digest',COMMIT),
                           ('--source-digest',COMMIT),('--source-ref','refs/tags/v'+VERSION),
                           ('--cert-identity','https://github.com/'+bundle.WORKFLOW+'@refs/tags/v'+VERSION)]:
            self.assertEqual(args[args.index(flag)+1],value)
        self.assertNotIn('--signer-workflow',args)  # Mutually exclusive with exact certificate identity.
        self.assertIn('--deny-self-hosted-runners',args)
        self.assertNotIn('--bundle',args)
        self.assertEqual(receipt['verification_sha256'],hashlib.sha256(answer).hexdigest())
        with patch.object(bundle,'bounded_command',return_value=b'[]'):
            with self.assertRaises(ValueError): bundle.verify_provenance(self.path,VERSION,COMMIT)

    def test_external_verifier_failure_output_and_deadline_are_bounded(self):
        for script,options in [
            ('raise SystemExit(1)',{}),
            ('print("x"*100000)',{'maximum':128}),
            ('import time; time.sleep(30)',{'timeout':.1})]:
            with self.assertRaises(ValueError): bundle.bounded_command([sys.executable,'-c',script],**options)
        self.assertEqual(bundle.bounded_command([sys.executable,'-c','print("ok")']),b'ok\n')


class StageTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name).resolve();self.releases=self.root/'releases';self.releases.mkdir()
        self.state=self.root/'state';self.state.mkdir()
        self.archive=self.root/'archive.tar.gz';fixture(self.archive)
        self.sha=bundle.digest(self.archive)
        self.gh=self.root/'gh';self.gh.write_text('test verifier');self.gh.chmod(0o755)
        self.patchers=[
            patch.object(stage,'RELEASES',self.releases),patch.object(stage,'GH',self.gh),
            patch.object(stage.platform,'machine',return_value='aarch64'),
            patch.object(stage.platform,'system',return_value='Linux'),
            patch.object(reservation,'CURRENT',self.root/'current'),
            patch.object(reservation,'STATE',self.state),patch.object(reservation,'ACTIVE',self.state/'active.json'),
            patch.object(reservation,'protected',side_effect=lambda path,*args:path.stat()),
            patch.object(stage.shutil,'disk_usage',return_value=type('Usage',(),{'free':8*1024**3})()),
            patch.object(bundle,'verify_provenance',return_value={'repository':bundle.REPOSITORY,'commit':COMMIT})]
        for p in self.patchers:p.start();self.addCleanup(p.stop)

    def run_stage(self):
        return stage.stage(self.archive,VERSION,COMMIT,self.sha)

    def test_staging_is_repeatable_and_never_changes_current_or_runs_archive_code(self):
        current=self.root/'current';current.symlink_to('releases/old')
        receipt=self.run_stage()
        self.assertEqual(current.readlink(),Path('releases/old'))
        self.assertEqual(self.run_stage()['archive_sha256'],receipt['archive_sha256'])
        self.assertTrue((self.state/('release-'+self.sha+'.json')).is_file())
        self.assertFalse(list(self.releases.glob('.noisefence-staging-*')))

    def test_failed_authentication_creates_no_release_or_receipt(self):
        with patch.object(bundle,'verify_provenance',side_effect=ValueError('untrusted signer')):
            with self.assertRaises(ValueError):self.run_stage()
        self.assertFalse((self.releases/VERSION).exists());self.assertEqual(list(self.state.iterdir()),[])
        self.assertFalse(list(self.releases.iterdir()))

    def test_wrong_transferred_digest_fails_before_verification(self):
        with patch.object(bundle,'verify_provenance') as verify:
            with self.assertRaisesRegex(ValueError,'checksum'):stage.stage(self.archive,VERSION,COMMIT,'b'*64)
        verify.assert_not_called()

    def test_existing_different_version_directory_is_never_overwritten(self):
        self.run_stage();binary=self.releases/VERSION/'noisefence';binary.write_bytes(b'changed')
        with self.assertRaises(ValueError):self.run_stage()
        self.assertEqual(binary.read_bytes(),b'changed')

    def test_failed_receipt_after_rename_recovers_without_replacing_release(self):
        with patch.object(stage,'atomic',side_effect=OSError('disk full')):
            with self.assertRaises(OSError):self.run_stage()
        before=(self.releases/VERSION/'noisefence').stat().st_ino
        self.assertEqual(self.run_stage()['archive_sha256'],self.sha)
        self.assertEqual((self.releases/VERSION/'noisefence').stat().st_ino,before)

    def test_reservation_and_low_disk_refuse_before_archive_verification(self):
        active=self.state/'active.json';active.write_text('{}')
        with self.assertRaisesRegex(ValueError,'owning upgrade'):self.run_stage()
        active.unlink()
        with patch.object(stage.shutil,'disk_usage',return_value=type('Usage',(),{'free':1024})()):
            with self.assertRaisesRegex(ValueError,'headroom'):self.run_stage()

    def test_non_linux_host_is_refused(self):
        with patch.object(stage.platform,'system',return_value='Darwin'):
            with self.assertRaisesRegex(ValueError,'requires Linux'):self.run_stage()
        self.assertFalse(list(self.releases.iterdir()))

    def test_verifier_gets_only_explicit_network_and_config_environment(self):
        with patch.dict(os.environ,{'GH_TOKEN':'synthetic','GH_HOST':'other.invalid','HTTPS_PROXY':'http://wrong.invalid'}):
            with patch.object(bundle,'verify_provenance',return_value={}) as verify:self.run_stage()
        env=verify.call_args.kwargs['env']
        self.assertEqual(env['GH_HOST'],'github.com');self.assertEqual(env['GH_TOKEN'],'synthetic')
        self.assertNotIn('HTTPS_PROXY',env)
        self.assertEqual(Path(env['GH_CONFIG_DIR']).parent.parent,self.releases)
