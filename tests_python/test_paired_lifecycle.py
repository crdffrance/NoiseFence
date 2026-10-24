"""Exercise fixture rejection/cleanup before any Docker process can be launched."""
import importlib.util
import io
import hashlib
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from tests_python import test_release_bundle as bundles

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('paired_fixture', ROOT/'tests/paired_release_lifecycle.py')
paired = importlib.util.module_from_spec(spec); spec.loader.exec_module(paired)


class PairedLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def archive(self, extra=None, release='0.31.8', **changes):
        path = self.root/f'noisefence-{release}-linux-arm64.tar.gz'
        top = path.name.removesuffix('.tar.gz')
        build = {'project':'NoiseFence','platform':'linux-arm64','version':release,
                 'storage_schema':7,'commit':'a'*40, **changes}
        raw = json.dumps(build).encode()
        with tarfile.open(path, 'w:gz') as output:
            member = tarfile.TarInfo(top+'/build.json'); member.size = len(raw)
            output.addfile(member, io.BytesIO(raw))
            if extra is not None:
                output.addfile(extra)
        Path(str(path)+'.sha256').write_text(paired.digest(path)+'  '+path.name+'\n')
        return path

    def test_checksum_platform_and_build_identity_are_bound(self):
        path = self.archive()
        self.assertEqual(paired.archive(path, 'arm64')['commit'], 'a'*40)
        with self.assertRaises(ValueError): paired.archive(path, 'amd64')
        Path(str(path)+'.sha256').write_text('0'*64+'\n')
        with self.assertRaisesRegex(ValueError, 'checksum'): paired.archive(path, 'arm64')
        for changes in [{'project':'other'}, {'version':'0.31.9'}, {'commit':'unknown'}, {'storage_schema':True}]:
            path = self.archive(**changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                paired.archive(path, 'arm64')

    def test_prerelease_archive_identity_is_preserved(self):
        for version in ['0.32.0-rc.1','1.0.0-beta.11']:
            result=paired.archive(self.archive(release=version),'arm64')
            self.assertEqual(result['version'],version)
        for version in ['1.0.0-rc.01','1.0.0+other','01.0.0']:
            with self.assertRaises(ValueError):paired.archive(self.archive(release=version),'arm64')

    def test_unsafe_link_and_duplicate_archive_members_fail_before_extraction(self):
        top = 'noisefence-0.31.8-linux-arm64'
        for name in ['/etc/passwd', top+'/../outside', top+'/./build.json']:
            path = self.archive(tarfile.TarInfo(name))
            with self.subTest(name=name), self.assertRaises(ValueError):
                paired.archive(path, 'arm64')
        member = tarfile.TarInfo(top+'/link'); member.type = tarfile.SYMTYPE; member.linkname = '/'
        with self.assertRaises(ValueError): paired.archive(self.archive(member), 'arm64')

    def test_validation_candidate_requires_exact_binary_platform_and_source(self):
        binary = self.root/'noisefence'
        binary.write_bytes(b'\x7fELF\x02\x01'+b'\x00'*12+(183).to_bytes(2,'little'))
        metadata = {'platform':'linux/arm64','version':'0.31.9','features':['semantic'],
                    'profile':'release','commit':'a'*40,'binary_sha256':paired.digest(binary),
                    'not_a_published_release':True}
        path = self.root/'candidate.json'; path.write_text(json.dumps(metadata))
        self.assertEqual(paired.validation_candidate(self.root,'arm64','0.31.9'),metadata)
        for key,value in [('platform','linux/amd64'),('features',[]),('profile','dev'),
                          ('commit','unknown'),('binary_sha256','0'*64),('not_a_published_release',False)]:
            path.write_text(json.dumps({**metadata,key:value}))
            with self.subTest(key=key),self.assertRaises(ValueError):paired.validation_candidate(self.root,'arm64','0.31.9')
        path.write_text(json.dumps(metadata));binary.write_bytes(b'not an ELF')
        with self.assertRaises(ValueError):paired.validation_candidate(self.root,'arm64','0.31.9')

    def complete_candidate_archive(self, missing=None):
        version='0.32.0-rc.1'; top='noisefence-'+version+'-linux-arm64'
        path=self.root/(top+'.tar.gz')
        def populate(files):
            for source in (ROOT/'deploy/postgresql').iterdir():
                if source.is_file():files['deploy/postgresql/'+source.name]=source.read_bytes()
            for name in ['noisefence.service','install.sh']:
                files['deploy/'+name]=(ROOT/'deploy'/name).read_bytes()
            if missing:files.pop(missing)
        with patch.object(bundles,'VERSION',version),patch.object(bundles,'TOP',top):
            files=bundles.fixture(path,change=populate)
        Path(str(path)+'.sha256').write_text(paired.digest(path)+'  '+path.name+'\n')
        return paired.archive(path,'arm64'),files

    def test_archive_candidate_keeps_exact_binary_metadata_manifest_and_helpers(self):
        item,files=self.complete_candidate_archive();destination=self.root/'extracted'
        metadata=paired.archive_candidate(item,'arm64',destination)
        for name in ['noisefence','build.json','SHA256SUMS',*('deploy/postgresql/'+p for p in metadata['helper_sha256'])]:
            self.assertEqual((destination/name).read_bytes(),files[name])
        self.assertEqual(metadata['binary_sha256'],hashlib.sha256(files['noisefence']).hexdigest())
        self.assertEqual(metadata['manifest_sha256'],hashlib.sha256(files['SHA256SUMS']).hexdigest())
        self.assertEqual(metadata['commit'],item['commit'])
        self.assertEqual(metadata['archive_sha256'],item['sha256'])
        self.assertEqual(metadata['origin'],'exact_archive')
        self.assertFalse(metadata['provenance_verified'])
        self.assertNotIn('qualification_candidate',json.loads((destination/'build.json').read_text()))

    def test_archive_candidate_rejects_missing_helpers_and_changed_input(self):
        for name in ['upgrade_exchange.py', 'rollback_check.py']:
            item,_=self.complete_candidate_archive(missing='deploy/postgresql/'+name)
            with self.subTest(helper=name), self.assertRaisesRegex(ValueError,'lacks'):
                paired.archive_candidate(item,'arm64',self.root/('missing-'+name))
        item,_=self.complete_candidate_archive()
        item['path'].write_bytes(item['path'].read_bytes()+b'changed')
        with self.assertRaisesRegex(ValueError,'changed'):
            paired.archive_candidate(item,'arm64',self.root/'changed')
        self.assertFalse((self.root/'changed').exists())

    def test_archive_lab_selects_deployment_files_from_archive_not_checkout(self):
        item,files=self.complete_candidate_archive()
        args=SimpleNamespace(output=self.root/'lab',platform='linux/arm64',
                             archive_candidate=True,validation_candidate=None)
        lab=paired.Lab(args,{'version':'0.31.9'},item)
        self.assertEqual(lab.candidate_release,item['version'])
        self.assertEqual(lab.candidate_directory,'/opt/noisefence/releases/'+item['version'])
        self.assertEqual(lab.deployment_source,lab.root/'candidate-archive/deploy')
        self.assertEqual((lab.deployment_source/'noisefence.service').read_bytes(),files['deploy/noisefence.service'])
        self.assertEqual(lab.validation_metadata['origin'],'exact_archive')

    def test_accepted_mail_requires_matching_origin_and_replica_bytes(self):
        lab = object.__new__(paired.Lab)
        lab.accepted = [{'node':'mx1','id':'message','body_sha256':'a'*64}]
        rows = {'mx1':{'message_ids':['message'],'bodies':{'message':'a'*64},
                       'replication_receipts':{'message':{'generation':2,'acked':1}},
                       'deliveries':[{'message_id':'message','address':'alice@example.test',
                                      'destination':'alice@example.test','status':'pending'}]},
                'mx2':{'replicas':{'message':'a'*64},
                       'remote_receipts':{'message':{'owner':'mx1','generation':1,
                                                    'body_sha256':'a'*64,'body_present':True}}}}
        lab.inspect = lambda: rows
        self.assertEqual(lab.verify_bodies(), rows)
        rows['mx2']['replicas']['message'] = 'b'*64
        with self.assertRaises(RuntimeError): lab.verify_bodies()
        rows['mx2']['replicas']['message'] = 'a'*64
        rows['mx1']['message_ids'] = []
        with self.assertRaises(RuntimeError): lab.verify_bodies()
        rows['mx1']['message_ids'] = ['message']
        rows['mx1']['replication_receipts']['message']['acked'] = 0
        with self.assertRaisesRegex(RuntimeError, 'receipt'): lab.verify_bodies()
        self.assertEqual(lab.verify_bodies(confirmed=False), rows)
        rows['mx1']['replication_receipts']['message']['acked'] = 1
        for field, invalid in [('owner','mx2'), ('body_sha256','c'*64), ('body_present',False), ('generation',0)]:
            previous = rows['mx2']['remote_receipts']['message'][field]
            rows['mx2']['remote_receipts']['message'][field] = invalid
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, 'receipt'):
                lab.verify_bodies()
            rows['mx2']['remote_receipts']['message'][field] = previous
        rows['mx1']['deliveries'][0]['destination'] = 'other@example.test'
        with self.assertRaisesRegex(RuntimeError, 'recipient'): lab.verify_bodies()

    def test_running_binary_must_match_verified_staged_archive(self):
        lab = object.__new__(paired.Lab)
        lab.binary_hashes = {'mx1':{'0.31.9':'a'*64}}
        result = {'running_release':'0.31.9','binary_sha256':'a'*64}
        lab.node = lambda *args: result
        self.assertEqual(lab.ready('mx1', '0.31.9'), result)
        result['binary_sha256'] = 'b'*64
        with self.assertRaises(RuntimeError): lab.ready('mx1', '0.31.9')
        result.update(binary_sha256='a'*64, running_release='0.31.8')
        with self.assertRaises(RuntimeError): lab.ready('mx1', '0.31.9')

    def test_health_without_fresh_expected_worker_exchange_is_not_ready(self):
        peers = [{'node':'mx2','build':'0.31.9','seen':101,'digest':'a'*64}]
        self.assertTrue(paired.policy_is_fresh(peers, '0.31.9', 100, 'a'*64, 102))
        self.assertFalse(paired.policy_is_fresh([], '0.31.9', 100, 'a'*64, 102))
        for changes in [{'node':'mx1'}, {'build':'0.31.8'}, {'seen':100}, {'seen':103},
                        {'seen':True}, {'seen':101.0}, {'digest':'b'*64}]:
            with self.subTest(changes=changes):
                self.assertFalse(paired.policy_is_fresh([{**peers[0], **changes}], '0.31.9', 100, 'a'*64, 102))

    def test_diagnostics_or_first_removal_failure_does_not_abandon_other_container(self):
        lab = object.__new__(paired.Lab); lab.root = self.root
        lab.created = ['mx1','mx2']; lab.names = {'mx1':'test-mx1','mx2':'test-mx2'}
        report = self.root/'paired-lifecycle-report.json'
        report.write_text(json.dumps({'status':'validated_pending_cleanup'}))
        calls = []
        def remove(*args, **kwargs):
            calls.append(args)
            if args[-1] == 'test-mx2': raise RuntimeError('Synthetic removal failure')
            return b''
        lab.run = remove
        lab.command = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError('Synthetic journal error'))
        with self.assertRaisesRegex(RuntimeError, 'cleanup'):
            lab.close()
        self.assertEqual([args[-1] for args in calls], ['test-mx2','test-mx1'])
        self.assertEqual(json.loads(report.read_text())['status'], 'cleanup_failed')
        self.assertFalse(json.loads(report.read_text())['cleanup'])
        self.assertEqual(len(json.loads((self.root/'cleanup.json').read_text())['failures']), 3)


if __name__ == '__main__':
    unittest.main()
