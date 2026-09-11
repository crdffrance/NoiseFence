"""Synthetic software checks, never a production accuracy evaluation."""
import copy
import importlib.util
import json
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

ROOT=Path(__file__).resolve().parents[1]
try:
    import numpy as np
    import scipy
    import sklearn
except ImportError:
    np=None


@unittest.skipIf(np is None,'Install research/requirements.txt')
class QualityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0,str(ROOT/'research'))
        import train_quality
        cls.q=train_quality
        cls.temp=tempfile.TemporaryDirectory()
        cls.root=Path(cls.temp.name)
        cls.data=cls.fixture()
        cls.path=cls.root/'sample.jsonl'
        cls.write(cls.path,cls.data)
        cls.report=cls.q.train(cls.path,cls.root/'candidate','SOFTWARE-TEST-ONLY')

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @staticmethod
    def write(path,rows):
        path.write_text(''.join(json.dumps(row)+'\n' for row in rows))

    @classmethod
    def fixture(cls):
        q=cls.q
        digest=lambda s:hashlib.sha256(s.encode()).hexdigest()
        now=int(time.time())
        data=[{'type':'header','schema':'noisefence-quality-dataset-1','batch':'software-fixture',
               'since':now-2000,'until':now-1,'population':1020,'selected':1020,
               'seed_sha256':digest('synthetic draw'), 'captured_at':now,
               'sampling':'uniform_message','protocol_sha256':q.PROTOCOL_HASH}]
        names=[f['name'] for f in q.PROTOCOL['features']]
        kind_features=['mailing.conversation','mailing.invoice_subject','mailing.notification_subject',
                       'mailing.newsletter_content','mailing.commercial_offer','mailing.service_message']
        for i in range(1020):
            identifier=digest('quality-row-'+str(i))
            spam=bool((i//6)%2)
            values=[0.]*len(names)
            values[names.index('lexical.logit_clipped_32')]=.6 if spam else -.6
            values[names.index(kind_features[i%6])]=1.
            observation={'schema':'noisefence-quality-observation-1','protocol_sha256':q.PROTOCOL_HASH,
                         'artifacts_sha256':digest('synthetic artifacts'),'source':'smtp_session',
                         'availability_profile':'complete/not_run/disabled','complete_features':True,'values':values,
                         'candidate_status':'not_configured','prediction':None,
                         'sender':{'status':'not_run','key':None,'legitimate_campaigns':0,'unwanted_campaigns':0,'observed_days':0,'conflict':False,'established':False}}
            data.append({'type':'row','id':identifier,'observed_at':now-1500+i,
                         'fingerprint':identifier,'simhash':identifier[:16],
                         'risk':'spam' if spam else 'legitimate','kind':q.KINDS[i%6],
                         'labelled_at':now,'legacy_decision':{'outcome':'undetermined'},'quality':observation})
        data.append({'type':'footer','rows':1020})
        return data

    def test_candidate_is_shadow_only_and_includes_calibration_ablation_and_intervals(self):
        report=self.report
        self.assertEqual(report['status'],'candidate_prepared')
        self.assertFalse(report['eligible'])
        self.assertTrue(report['observation_only'])
        self.assertEqual(len(report['ablations']),4)
        self.assertIsNotNone(report['risk']['test']['fpr_ci95'])
        self.assertGreater(report['risk']['test']['fpr_ci95'][1],.001)
        self.assertEqual(len(report['mail_kind']['confusion']),6)
        self.assertEqual(report['test_unit'],'one_representative_per_campaign')

    def test_duplicate_campaigns_and_conflicts_cannot_cross_partitions(self):
        _,rows,_,_,_=self.q.load_dataset(self.path)
        altered=copy.deepcopy(rows)
        altered[-1]['fingerprint']=altered[0]['fingerprint']
        altered[-1]['campaign']=altered[0]['campaign']
        parts,counts=self.q.partition(altered)
        self.assertEqual(counts['cross_period_campaigns'],1)
        retained={r['id'] for part in parts.values() for r in part}
        self.assertNotIn(altered[0]['id'],retained)
        self.assertNotIn(altered[-1]['id'],retained)
        altered=copy.deepcopy(rows)
        altered[1]['fingerprint']=altered[0]['fingerprint']
        altered[1]['campaign']=altered[0]['campaign']
        _,counts=self.q.partition(altered)
        self.assertEqual(counts['conflicting_campaigns'],1)

    def test_unknown_labels_are_not_replaced_by_model_predictions(self):
        data=copy.deepcopy(self.data)
        for row in data[1:-1]:
            row['risk']=None;row['kind']=None;row['labelled_at']=None
        path=self.root/'unlabelled.jsonl';self.write(path,data)
        report=self.q.train(path,self.root/'no-model','SOFTWARE-TEST-ONLY')
        self.assertEqual(report['status'],'insufficient_labels')
        self.assertFalse((self.root/'no-model').exists())

    def test_unseen_profiles_count_as_abstentions_instead_of_correct_predictions(self):
        q=self.q
        report=q.metrics(np.array([1,0]),np.array([.99,.01]),.2,.8,np.array([False,False]))
        self.assertEqual(report['tp'],0)
        self.assertEqual(report['review'],2)
        self.assertEqual(report['spam_missed_or_review'],1)
        self.assertEqual(report['unsupported_profile'],2)
        self.assertIsNone(report['brier'])

    def test_exports_reject_changed_artifacts_invalid_values_and_duplicate_ids(self):
        for change in ('artifact','value','identity'):
            data=copy.deepcopy(self.data)
            if change=='artifact':data[2]['quality']['artifacts_sha256']='1'*64
            if change=='value':data[2]['quality']['values'][0]=float('inf')
            if change=='identity':data[2]['id']=data[1]['id']
            path=self.root/(change+'.jsonl');self.write(path,data)
            with self.assertRaises(ValueError):self.q.load_dataset(path)

    def test_base_model_or_previous_test_campaign_overlap_is_rejected(self):
        row=self.data[1]
        history=self.root/'base-history.jsonl'
        self.write(history,[{'fingerprint':row['fingerprint'],'campaign':row['fingerprint'],'simhash':row['simhash']}])
        with self.assertRaisesRegex(ValueError,'overlaps'):
            self.q.train(self.path,self.root/'overlap-model','SOFTWARE-TEST-ONLY',history)

    @unittest.skipUnless(os.environ.get('NOISEFENCE_BINARY'),'Native binary configured by semantic CI')
    def test_native_risk_and_six_kind_probabilities_match_python(self):
        binary=str(Path(os.environ['NOISEFENCE_BINARY']).resolve())
        candidate=self.root/'candidate'
        for i,probe in enumerate(json.loads((candidate/'parity.json').read_text())):
            path=self.root/f'probe-{i}.json';path.write_text(json.dumps(probe['observation']))
            result=json.loads(subprocess.check_output([binary,'quality-predict','--model',str(candidate/'model.json'),'--observation',str(path)],text=True))
            self.assertAlmostEqual(result['risk_probability'],probe['risk_probability'],places=9)
            np.testing.assert_allclose(result['kind_probabilities'],probe['kind_probabilities'],atol=1e-9,rtol=1e-9)
            self.assertTrue(result['observation_only'])


if __name__=='__main__':unittest.main()
