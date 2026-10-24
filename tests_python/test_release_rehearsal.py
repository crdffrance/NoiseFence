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
            for name in ['upgrade_validation.py','upgrade_activation.py','upgrade_exchange.py','rollback_check.py','rollback_validation.py','rollback_promotion.py','rollback_activation.py']:
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
                      'idempotent_reinstall','stopped_service_preserves_accepted_body_and_queue','unit_removed_data_retained',
                      'disk_full_before_mail_temporarily_rejected','disk_full_after_data_temporarily_rejected',
                      'disk_full_recovery_preserves_accepted_messages']}
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
                'unqualified_downgrade_and_replacement_refused',
                'candidate_expired_stopped_and_preserved_selected_data',
                'candidate_peer_loss_invalidates_readiness','mandatory_peer_outage_deferred',
                'committed_start_failure_recovered_forward_and_auxiliary_jobs_held',
                'actual_ssh_completion_reply_lost_after_durable_finish',
                'native_pair_completed_over_pinned_ssh_after_proof_expiry',
                'rollback_identities_checked_without_downgrade_authority','retained_validation_keeps_normal_writers_held',
                'normal_candidates_verified_and_operation_completed']],
            'not_qualified':['detection_accuracy','archive_provenance'],
            'final_state':{'password':'never upload','message':'never upload'}}

    def summarize(self, kind="historical"):
        (self.root/'paired/paired-lifecycle-report.json').write_text(json.dumps(self.paired))
        (self.root/'standalone/lifecycle-report.json').write_text(json.dumps(self.standalone))
        return rehearsal.summarize(self.platform,self.archive,self.root,version=self.version,commit=self.commit,kind=kind)

    def test_retained_gate_requires_positive_runtime_and_reverse_activation_evidence(self):
        with patch.object(rehearsal,'RETAINED_BASELINE',rehearsal.BASELINE):
            with self.assertRaisesRegex(ValueError,'Positive retained'):self.summarize(kind='retained')
            self.paired['checks'] += [
                {'check':'retained_pair_activated_with_current_mail_and_lost_replies',
                 'retained_version':self.pin['version'],'source_version':self.version,'database_restored':False,'database_unchanged_before_start':True,
                 'protocol':'noisefence-retained-activation-1','start_reply_lost':True,'finish_reply_lost':True},
                {'check':'new_forward_operation_after_completed_rollback'}]
            with self.assertRaisesRegex(ValueError,'Unsupported or skipped'):self.summarize(kind='retained')
            probe=next(r for r in self.paired['checks'] if r['check']=='retained_validation_keeps_normal_writers_held')
            probe.update(validation_ready=True,retained_command_supported=True)
            self.assertEqual(self.summarize(kind='retained')['baseline_kind'],'retained')
            self.paired['not_qualified'].append('post_activation_rollback')
            with self.assertRaisesRegex(ValueError,'Incomplete retained'):self.summarize(kind='retained')
            self.paired['not_qualified'].remove('post_activation_rollback')
            for key,value in [('database_restored',True),('retained_version','0.0.1'),('start_reply_lost',False)]:
                row=self.paired['checks'][-2];previous=row[key];row[key]=value
                with self.assertRaises(ValueError):self.summarize(kind='retained')
                row[key]=previous

    def test_retained_pin_is_explicit_and_does_not_replace_historical_baseline(self):
        old=rehearsal.baseline()
        retained=rehearsal.baseline('retained')
        self.assertEqual(retained['version'],'0.32.0-rc.1')
        self.assertEqual(old['version'],self.pin['version'])
        self.assertNotEqual(retained['archives'],old['archives'])
        with self.assertRaisesRegex(ValueError,'Unknown baseline'):rehearsal.baseline('automatic-latest')

    def test_success_emits_bound_identity_and_counts_without_private_fixture_details(self):
        result = self.summarize()
        self.assertEqual(result['archive_sha256'], self.sha)
        self.assertEqual(result['accepted_synthetic_messages'],24)
        self.assertEqual(result['baseline']['commit'],self.pin['commit'])
        self.assertFalse(result['provenance_verified'])
        self.assertFalse(result['rehearsal_only'])
        self.assertNotIn('never upload',json.dumps(result))
        self.assertNotIn('final_state',result); self.assertNotIn('accepted',result)

    def test_unconfined_reports_make_no_confinement_claim(self):
        self.assertEqual(self.summarize()['confinement'], {'status':'not_exercised'})

    def test_confinement_needs_source_binding_both_canaries_runtimes_and_cleanup(self):
        name = 'noisefence-test-0123456789ab'
        binary = 'a'*64; generator = 'b'*64
        files = {'noisefence':binary,'deploy/hardening/isolation.py':generator,'deploy/noisefence.service':'e'*64}
        runtime = {'profile':name,'process_profile':name+' (enforce)','mode':'enforce','binary_sha256':binary}
        paired = {'apparmor_profile':name,'confinement_scope':'named_profile_enforcement_with_dac_canary',
            'platform':'linux/arm64','checks':[],
            'final_running':{node:{'confinement':dict(runtime)} for node in ('mx1','mx2')}}
        for node in ('mx1','mx2'):
            paired['checks'].extend([
                {'check':'apparmor_canary_enforced','node':node,'profile':name,
                 'allowed_configuration':True,'unconfined_canary_read':True,'confined_canary_denied':True},
                {'check':'candidate_apparmor_enforced','node':node,**runtime}])
        proof = {'schema':'noisefence-confinement-rehearsal-1','status':'passed','profile':name,
            'profile_removed':True,'production_affected':False,'platform':'linux/arm64',
            'profile_sha256':'c'*64,'generator_sha256':generator,'renderer_sha256':'d'*64}
        folder = self.root/'apparmor';folder.mkdir()
        path = folder/'confinement.json';path.write_text(json.dumps(proof))
        socket={'schema':'noisefence-postgres-confinement-probe-3','status':'passed','production_affected':False,
            'container_removed':True,'profile_removed':True,'generator_sha256':generator,'renderer_sha256':'d'*64,
            'service_sha256':'e'*64,'binary_sha256':'f'*64,'unconfined':'query_ok','confined':'query_ok',
            'service_context':{'unconfined':'query_ok','confined':'query_ok'},
            'scoped_attachment_diagnostic':{'result':'query_ok'},
            'scope_boundary_diagnostic':{'scope':'query5432_with_only_disconnected5433_allowed_must_be_denied',
                'verified':True,'result':'socket_permission_denied'}}
        socket_folder=self.root/'socket-boundary';socket_folder.mkdir();socket_path=socket_folder/'probe.json'
        with self.assertRaises(FileNotFoundError):rehearsal.confinement_summary(self.root,paired,files)
        socket_path.write_text(json.dumps(socket))
        result=rehearsal.confinement_summary(self.root,paired,files)
        self.assertEqual(result['status'],'enforced');self.assertEqual(result['socket_boundary']['status'],'verified')
        for key,value in [('generator_sha256','0'*64),('renderer_sha256','0'*64),('service_sha256','0'*64),
                          ('container_removed',False),('profile_removed',False),('binary_sha256','bad'),
                          ('service_context',{'unconfined':'query_ok','confined':'socket_permission_denied'}),
                          ('scope_boundary_diagnostic',{'verified':True,'result':'query_ok'}),
                          ('scoped_attachment_diagnostic',{'result':'socket_permission_denied'})]:
            socket_path.write_text(json.dumps({**socket,key:value}))
            with self.subTest(socket_key=key),self.assertRaises(ValueError):rehearsal.confinement_summary(self.root,paired,files)
        for invalid_digest in (None, '', 'not-a-digest'):
            absent_binding={**files,'deploy/noisefence.service':invalid_digest}
            socket_path.write_text(json.dumps({**socket,'service_sha256':invalid_digest}))
            with self.subTest(service_digest=invalid_digest),self.assertRaises(ValueError):
                rehearsal.confinement_summary(self.root,paired,absent_binding)
        missing_binding=dict(files);missing_binding.pop('deploy/noisefence.service')
        missing_socket=dict(socket);missing_socket.pop('service_sha256')
        socket_path.write_text(json.dumps(missing_socket))
        with self.assertRaises(ValueError):rehearsal.confinement_summary(self.root,paired,missing_binding)
        socket_path.write_text(json.dumps(socket))
        for key,value in [('profile_removed',False),('profile','other'),('generator_sha256','e'*64),
                          ('profile_sha256','bad'),('status','failed'),('platform','linux/amd64')]:
            path.write_text(json.dumps({**proof,key:value}))
            with self.subTest(key=key),self.assertRaises(ValueError):rehearsal.confinement_summary(self.root,paired,files)
        path.write_text(json.dumps(proof))
        for change in ('canary','candidate','final'):
            altered = copy.deepcopy(paired)
            if change == 'canary':altered['checks'][0]['confined_canary_denied'] = False
            if change == 'candidate':altered['checks'][1]['binary_sha256'] = 'f'*64
            if change == 'final':altered['final_running']['mx2']['confinement']['mode'] = 'complain'
            with self.subTest(change=change),self.assertRaises(ValueError):rehearsal.confinement_summary(self.root,altered,files)
        with self.assertRaises(ValueError):rehearsal.confinement_summary(self.root,{},files)


    def test_native_confinement_requires_the_socket_positive_and_negative_stage(self):
        script=(ROOT/'scripts/check_release_lifecycle.sh').read_text()
        self.assertIn('phase=socket-boundary',script)
        self.assertIn('rustc --edition=2024 --test tests/fixtures/postgres_socket_probe.rs',script)
        self.assertIn('tests/confinement_socket_probe.py --binary "$output/socket-probe"',script)
        self.assertLess(script.index('phase=socket-boundary'),script.index('phase=paired\n'))
        self.assertIn('set -eu',script)

    def test_failed_partial_wrong_platform_and_local_binary_runs_are_refused(self):
        original = copy.deepcopy(self.paired)
        for key,value in [('status','failed'),('cleanup',False),('candidate_mode','local_binary'),
                          ('platform','linux/amd64'),('production_affected',True),('archive_commits',{})]:
            self.paired = {**original,key:value}
            with self.subTest(key=key),self.assertRaises(ValueError): self.summarize()

    def test_historical_standalone_run_without_storage_pressure_cannot_qualify(self):
        self.standalone['checks'] = [check for check in self.standalone['checks']
                                     if not check.startswith('disk_full_')]
        with self.assertRaisesRegex(ValueError, 'Standalone lifecycle coverage'):
            self.summarize()

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

    def test_historical_run_without_rollback_identity_inspection_cannot_qualify(self):
        self.paired['checks'] = [row for row in self.paired['checks']
            if row['check'] != 'rollback_identities_checked_without_downgrade_authority']
        with self.assertRaisesRegex(ValueError, 'Required native recovery coverage'):
            self.summarize()

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
