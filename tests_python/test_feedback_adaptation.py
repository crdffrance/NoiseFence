"""Corrective learning must preserve controls and measure unseen campaigns."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
try:
    import numpy as np
    from scipy import sparse
except ImportError:
    np=None


@unittest.skipIf(np is None, 'Install research/requirements.txt')
class FeedbackAdaptation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0,str(ROOT/'research'))
        spec=importlib.util.spec_from_file_location('adapt_feedback',ROOT/'research/adapt_feedback.py')
        cls.m=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.m)

    def test_residual_corrects_labelled_direction_and_preserves_orthogonal_mail(self):
        x=sparse.csr_matrix([[1.,0.,0.],[0.,1.,0.]])
        y=np.array([False,True])
        base=np.array([5.,-5.])
        replay=sparse.csr_matrix([[0.,0.,1.],[0.,0.,1.]])
        delta=self.m.fit_residual(x,y,base,replay,y,np.array([-5.,5.]))
        self.assertLess(delta[0],0)
        self.assertGreater(delta[1],0)
        self.assertEqual(delta[2],0)
        self.assertLess(np.linalg.norm(delta),np.linalg.norm(base))
        np.testing.assert_allclose(x @ (np.array([5.,-5.,1.])+delta),base+x @ delta)

    def test_replay_resists_forgetting_without_becoming_a_whitelist(self):
        x=sparse.eye(2,format='csr')
        y=np.array([False,True]);base=np.array([5.,-5.])
        light=self.m.fit_residual(x,y,base,x,~y,base,replay_weight=.01)
        strong=self.m.fit_residual(x,y,base,x,~y,base,replay_weight=100.)
        self.assertGreater(np.linalg.norm(light),np.linalg.norm(strong))
        # There is no sender/domain bypass and no arbitrary overwrite of logits.
        self.assertGreater((base+strong)[0],0)

    def test_transitive_campaign_dates_and_conflicts_are_preserved(self):
        rows=[]
        for i,h in enumerate((0,7,63)):
            key=hashlib.sha256(str(i).encode()).hexdigest()
            rows.append({'id':key,'fingerprint':key,'simhash':f'{h:016x}',
                         'observed_at':100+i*100,'labelled_at':400+i,'spam':False})
        grouped,report=self.m.group_rows(rows)
        self.assertEqual(report['retained'],1)
        self.assertEqual(grouped[0]['observed_at'],100)
        self.assertEqual(grouped[0]['last_observed_at'],300)
        self.assertEqual(grouped[0]['labelled_at'],402)
        rows[-1]['spam']=True
        self.assertEqual(self.m.group_rows(rows)[0],[])

    def replay(self):
        rows=[]
        for i in range(100):
            key=hashlib.sha256(str(i).encode()).hexdigest()
            source={'fingerprint':key,'group':key}
            part=self.m.partition([source])
            name='train' if len(part['train']) else 'control' if len(part['test']) else None
            if name:
                rows.append({'schema':'noisefence-content-replay-1','feature_version':3,
                             'id':key,'group':key,'fingerprint':key,'simhash':key[:16],
                             'spam':bool(i%2),'features':[[i,1.]],'stratum':'historical','partition':name})
        return rows

    def read_replay(self,rows):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'rows.jsonl'
            path.write_text(''.join(json.dumps(row)+'\n' for row in rows))
            return self.m.load_replay(path)

    def test_holdouts_and_duplicate_campaigns_cannot_enter_replay_training(self):
        rows=self.replay()
        self.assertEqual(len(self.read_replay(rows)),len(rows))
        altered=copy.deepcopy(rows)
        next(r for r in altered if r['partition']=='control')['partition']='train'
        with self.assertRaisesRegex(ValueError,'Reserved'):
            self.read_replay(altered)
        duplicate=copy.deepcopy(rows[0]);duplicate['id']='f'*64
        with self.assertRaisesRegex(ValueError,'representative'):
            self.read_replay(rows+[duplicate])

    def test_invalid_vectors_and_external_training_are_rejected(self):
        for pairs in ([[1,float('nan')]], [[True,1.]], [[1,.2]], [[1,1.],[1,1.]]):
            rows=self.replay();rows[0]['features']=pairs
            with self.assertRaises(ValueError):self.read_replay(rows)
        rows=self.replay()
        next(r for r in rows if r['partition']=='train')['external_test']=True
        with self.assertRaisesRegex(ValueError,'Reserved'):self.read_replay(rows)

    def test_temporal_control_refuses_delayed_labels_and_test_vectors_do_not_fit(self):
        from unittest.mock import patch
        rows=[]
        for i in range(10):
            key=hashlib.sha256(f'feedback-{i}'.encode()).hexdigest()
            rows.append({'id':key,'fingerprint':key,'simhash':key[:16],
                         'features':[[i,1.]],'spam':bool(i%2),'observed_at':100+i,
                         'labelled_at':1000})
        model={'weights':[0.]*self.m.DIMENSION,'idf':[1.]*self.m.DIMENSION,'bias':0.}
        seen=[]
        def fake_fit(x,labels,base,replay_x,replay_labels,replay_base,*args):
            seen.append(x.shape[0])
            return np.zeros(self.m.DIMENSION)
        with patch.object(self.m,'fit_residual',side_effect=fake_fit):
            candidate,report=self.m.evaluate(rows,model,None,self.replay())
        self.assertEqual(seen,[9]*10+[10])
        self.assertEqual(report['temporal']['status'],'insufficient_past_labels')
        self.assertFalse(report['eligible'])
        self.assertEqual(candidate['bias'],model['bias'])
        self.assertEqual(candidate['idf'],model['idf'])
        self.assertEqual(report['campaign_out']['candidate']['spam'],5)

    def test_baseline_head_is_bound_to_exact_model_and_protocol(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'model.json';head=Path(tmp)/'head.json'
            model={'algorithm':'logistic','feature_version':3,'weights':[0.]*self.m.DIMENSION,
                   'idf':[1.]*self.m.DIMENSION,'bias':0.}
            path.write_text(json.dumps(model))
            self.m.load_baseline(path,None)
            head.write_text(json.dumps({'schema':'noisefence-hybrid-1',
                                       'lexical_model_sha256':'0'*64,'threshold':95}))
            with self.assertRaisesRegex(ValueError,'bound'):
                self.m.load_baseline(path,head)

    def test_fewer_false_positives_never_hides_lost_capture(self):
        cohort={'baseline':{'false_positive':8,'true_positive':7},
                'candidate':{'false_positive':0,'true_positive':2}}
        report={'campaign_out':cohort,'lexical_replay_controls':{},
                'temporal':{'status':'insufficient_past_labels'}}
        gate=self.m.regression_gate(report)
        self.assertEqual(gate['status'],'rejected')
        self.assertIn('campaign_out:lower_capture',gate['reasons'])
        cohort['candidate']['true_positive']=8
        report['temporal']={'status':'complete',**cohort}
        gate=self.m.regression_gate(report)
        self.assertEqual(gate['status'],'needs_independent_validation')
        self.assertFalse(gate['may_activate'])

    @unittest.skipUnless(os.environ.get('NOISEFENCE_FEEDBACK_PROBE'), 'Build native feedback_probe')
    def test_folded_candidate_matches_native_rust_without_new_inference_cost(self):
        model={'version':'synthetic-residual','algorithm':'logistic','feature_version':3,
               'weights':[0.]*self.m.DIMENSION,'idf':[1.]*self.m.DIMENSION,
               'bias':4.,'trained_at':100,'examples':2}
        model['idf'][:2]=[2.,3.]
        vector=[.6,.8]+[0.]*382
        rows=[{'id':hashlib.sha256(str(i).encode()).hexdigest(),
               'features':[[i,1.]],'semantic':{'features':vector,'protocol':self.m.PROTOCOL}}
              for i in range(2)]
        x=self.m.transformed(rows,model)
        base=self.m.baseline_logits(x,rows,model,None)
        y=np.array([False,True])
        delta=self.m.fit_residual(x,y,base,x,y,base)
        candidate={**model,'weights':(np.array(model['weights'])+delta).tolist()}
        head={k:self.m.PROTOCOL[k] for k in ('encoder','revision','text_schema','max_tokens')}
        head.update(schema='noisefence-hybrid-1',version='synthetic-head',head_weights=[.1]*384,
                    head_bias=-1.,semantic_weight=.1,score_bias_delta=.2,threshold=95.)
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp);bundle=path/'candidate';data=path/'input.jsonl'
            data.write_text(''.join(json.dumps(r)+'\n' for r in rows))
            self.m.publish(bundle,candidate,head,{'eligible':False},[],aggregate_only=True)
            result=subprocess.check_output([os.environ['NOISEFENCE_FEEDBACK_PROBE'],
                str(bundle/'model.json'),str(bundle/'native-combination.json'),str(data)],text=True,timeout=30)
            native=[json.loads(line)['combined_logit'] for line in result.splitlines()]
            expected=self.m.baseline_logits(x,rows,candidate,head)
            np.testing.assert_allclose(native,expected,rtol=0,atol=1e-10)
            self.assertFalse((bundle/'predictions.json').exists())


if __name__=='__main__':unittest.main()
