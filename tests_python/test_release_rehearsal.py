"""Bind anonymous native qualification evidence to reviewed, unchanged archives."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
from tests_python import test_release_bundle as archives

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
spec = importlib.util.spec_from_file_location('release_rehearsal', ROOT/'scripts/release_rehearsal.py')
rehearsal = importlib.util.module_from_spec(spec); spec.loader.exec_module(rehearsal)
sys.path.pop(0)


class RehearsalTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name); self.platform = 'linux-arm64'
        self.version = '0.32.0-rc.1'; self.commit = 'b'*40
        self.pin = rehearsal.baseline()
        (self.root/'baseline').mkdir(); (self.root/'paired').mkdir(); (self.root/'standalone').mkdir()
        self.old = self.root/'baseline'/rehearsal.baseline_name(self.pin, self.platform)
        with patch.object(archives, 'COMMIT', self.pin['commit']): archives.fixture(self.old)
        self.pin['archives'][self.platform] = rehearsal.bundle.digest(self.old)
        pin_file = self.root/'baseline.json'; pin_file.write_text(json.dumps(self.pin))
        patcher = patch.object(rehearsal, 'BASELINE', pin_file); patcher.start(); self.addCleanup(patcher.stop)
        self.archive = self.root/('noisefence-'+self.version+'-'+self.platform+'.tar.gz')
        def helpers(files):
            for name in ['upgrade_validation.py','upgrade_activation.py','upgrade_exchange.py']:
                files['deploy/postgresql/'+name] = b'synthetic helper; never executed'
        with patch.object(archives,'VERSION',self.version), patch.object(archives,'COMMIT',self.commit), patch.object(archives,'TOP',self.archive.name.removesuffix('.tar.gz')):
            archives.fixture(self.archive, change=helpers)
        self.sha = rehearsal.bundle.digest(self.archive)
        Path(str(self.archive)+'.sha256').write_text(self.sha+'  '+self.archive.name+'\n')
        files = rehearsal.bundle.inspect_archive(self.archive,self.version,self.platform,self.commit)['files']
        digests = {self.pin['version']:self.pin['archives'][self.platform], self.version:self.sha}
        self.standalone = {'status':'passed','cleanup':True,'production_affected':False,'platform':'linux/arm64',
            'archive_sha256':digests,'versions':[self.pin['version'],self.version],
            'checks':['fresh_install_0.31.9','synthetic_smtp_acceptance','upgrade_'+self.version,
                      'idempotent_reinstall','stopped_service_preserves_accepted_body_and_queue','unit_removed_data_retained']}
        helpers = {name.rsplit('/',1)[1]:digest for name,digest in files.items() if name.startswith('deploy/postgresql/')}
        self.paired = {'status':'passed','production_affected':False,'platform':'linux/arm64',
            'archive_sha256':digests,'cleanup':True,'candidate_mode':'exact_archive',
            'archive_commits':{self.pin['version']:self.pin['commit'],self.version:self.commit},
            'installed_helper_sha256':{'mx1':helpers,'mx2':helpers},
            'validation_candidate':{'origin':'exact_archive','version':self.version,'commit':self.commit,
                'archive_sha256':self.sha,'binary_sha256':files['noisefence'],
                'build_sha256':files['build.json'],'manifest_sha256':files['SHA256SUMS']},
            'final_running':{node:{'smtp_ready':True,'running_release':self.version,'binary_sha256':files['noisefence']} for node in ['mx1','mx2']},
            'accepted':[{'id':str(i),'node':'mx1' if i%2 else 'mx2','private':'never upload'} for i in range(24)],
            'checks':[{'check':name,'private':'never upload'} for name in [
                'candidate_expired_stopped_and_preserved_selected_data',
                'candidate_peer_loss_invalidates_readiness','mandatory_peer_outage_deferred',
                'committed_start_failure_recovered_forward_and_auxiliary_jobs_held',
                'actual_ssh_completion_reply_lost_after_durable_finish',
                'native_pair_completed_over_pinned_ssh_after_proof_expiry',
                'normal_candidates_verified_and_operation_completed']],
            'not_qualified':['detection_accuracy','archive_provenance'],
            'final_state':{'password':'never upload','message':'never upload'}}

    def summarize(self):
        (self.root/'paired/paired-lifecycle-report.json').write_text(json.dumps(self.paired))
        (self.root/'standalone/lifecycle-report.json').write_text(json.dumps(self.standalone))
        return rehearsal.summarize(self.platform,self.archive,self.root,version=self.version,commit=self.commit)

    def test_success_emits_bound_identity_and_counts_without_private_fixture_details(self):
        result = self.summarize()
        self.assertEqual(result['archive_sha256'], self.sha)
        self.assertEqual(result['accepted_synthetic_messages'],24)
        self.assertEqual(result['baseline']['commit'],self.pin['commit'])
        self.assertFalse(result['provenance_verified'])
        self.assertFalse(result['rehearsal_only'])
        self.assertNotIn('never upload',json.dumps(result))
        self.assertNotIn('final_state',result); self.assertNotIn('accepted',result)

    def test_failed_partial_wrong_platform_and_local_binary_runs_are_refused(self):
        original = copy.deepcopy(self.paired)
        for key,value in [('status','failed'),('cleanup',False),('candidate_mode','local_binary'),
                          ('platform','linux/amd64'),('production_affected',True),('archive_commits',{})]:
            self.paired = {**original,key:value}
            with self.subTest(key=key),self.assertRaises(ValueError): self.summarize()

    def test_standalone_cleanup_must_be_explicitly_verified(self):
        for value in [None, False, 'true']:
            self.standalone['cleanup'] = value
            with self.subTest(cleanup=value), self.assertRaisesRegex(ValueError, 'cleanup'):
                self.summarize()
        self.standalone['cleanup'] = True
        self.standalone['status'] = 'cleanup_failed'
        with self.assertRaisesRegex(ValueError, 'did not pass'):
            self.summarize()

    def test_actual_candidate_bytes_and_both_running_identities_are_required(self):
        self.paired['validation_candidate']['manifest_sha256']='0'*64
        with self.assertRaises(ValueError): self.summarize()
        self.paired['validation_candidate']['manifest_sha256']=rehearsal.bundle.inspect_archive(self.archive,self.version,self.platform,self.commit)['files']['SHA256SUMS']
        self.paired['final_running']['mx2']['smtp_ready']=False
        with self.assertRaises(ValueError): self.summarize()
        self.paired['final_running']['mx2']['smtp_ready']=True
        self.paired['installed_helper_sha256']['mx1']={}
        with self.assertRaises(ValueError): self.summarize()

    def test_missing_recovery_and_standalone_coverage_cannot_create_success(self):
        self.paired['checks'].pop()
        with self.assertRaisesRegex(ValueError,'coverage'): self.summarize()
        self.paired['checks'].append({'check':'normal_candidates_verified_and_operation_completed'})
        self.standalone['checks']=[]
        with self.assertRaisesRegex(ValueError,'coverage'): self.summarize()

    def test_mismatched_archive_receipts_duplicate_acceptances_and_changed_baseline_fail(self):
        self.standalone['archive_sha256']={}
        with self.assertRaises(ValueError): self.summarize()
        self.standalone['archive_sha256']=self.paired['archive_sha256']
        self.paired['accepted'][1]['id']=self.paired['accepted'][0]['id']
        with self.assertRaises(ValueError): self.summarize()
        self.paired['accepted'][1]['id']='1'
        self.old.write_bytes(b'changed baseline')
        with self.assertRaisesRegex(ValueError,'Baseline changed'): self.summarize()

    def test_fetch_binds_public_repository_host_hash_commit_and_architecture(self):
        destination=self.root/'download'
        def download(command,**kwargs):
            self.assertEqual(command[command.index('--repo')+1],'crdffrance/NoiseFence')
            self.assertEqual(kwargs['env']['GH_HOST'],'github.com')
            shutil.copyfile(self.old,destination/self.old.name)
            return b''
        with patch.object(rehearsal.bundle,'bounded_command',side_effect=download), patch.dict(os.environ,{'GH_HOST':'wrong.invalid'}):
            result=rehearsal.fetch_baseline(self.platform,destination)
        self.assertEqual(rehearsal.bundle.digest(result),self.pin['archives'][self.platform])
        self.assertTrue(Path(str(result)+'.sha256').exists())
        with self.assertRaises(FileExistsError):rehearsal.fetch_baseline(self.platform,destination)

    def test_wrong_downloaded_bytes_do_not_gain_a_checksum_receipt(self):
        destination=self.root/'wrong'
        def download(*args,**kwargs):
            (destination/self.old.name).write_bytes(b'wrong bytes')
            return b''
        with patch.object(rehearsal.bundle,'bounded_command',side_effect=download):
            with self.assertRaisesRegex(ValueError,'reviewed checksum'): rehearsal.fetch_baseline(self.platform,destination)
        self.assertFalse(Path(str(destination/self.old.name)+'.sha256').exists())

    def test_invalid_baseline_fails_before_network_use(self):
        self.pin['archives']['linux-arm64']='bad'
        rehearsal.BASELINE.write_text(json.dumps(self.pin))
        with patch.object(rehearsal.bundle,'bounded_command') as run:
            with self.assertRaises(ValueError):rehearsal.fetch_baseline(self.platform,self.root/'invalid')
        run.assert_not_called()
