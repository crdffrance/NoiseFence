import copy
import hashlib
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'research'))
try:
    import calibrate_evidence as m
    import numpy as np
except ImportError:
    m=None


@unittest.skipIf(m is None,'Install research/requirements.txt')
class EvidenceCalibration(unittest.TestCase):
    def evidence(self):
        return {'schema':'noisefence-evidence-1','source':'smtp_session',
                'lexical_state':'complete','lexical_logit':4.,
                'semantic_state':'complete','semantic_logit':3.,
                'llm':{'state':'complete','outcome':'complete','category':'legitimate',
                       'reported_probability':.1,'reported_confidence':.9},
                'authentication':{'state':'complete','dmarc_state':'complete','dmarc_dkim':'pass'}}

    def rows(self):
        rows=[]
        for i in range(14):
            key=hashlib.sha256(str(i).encode()).hexdigest()
            spam=bool(i%2)
            rows.append({'id':key,'fingerprint':key,'campaign':key,'simhash':key[:16],
                         'spam':spam,'observed_at':100+i,'labelled_at':100+i,
                         'values':[.5,.5,1. if spam else -.8,-1.,0.,0.,0.,0.],
                         'profile':'complete','legacy_score':99.,'provenance':{},'llm_prompt':'test'})
        return rows

    def test_missing_or_incoherent_results_never_become_benign_evidence(self):
        e=self.evidence();values,_=m.vector(e)
        self.assertLess(values[2],0);self.assertEqual(values[3],-1)
        e['llm']['state']='unavailable';e['authentication']['dmarc_state']='unavailable'
        values,_=m.vector(e);self.assertEqual(values[2],0);self.assertEqual(values[3],0)
        e['llm']['state']='complete';e['llm']['reported_probability']=.9
        self.assertEqual(m.vector(e)[0][2],0)
        e['source']='supplied_envelope'
        with self.assertRaises(ValueError):m.vector(e)

    def test_risk_coefficients_cannot_invert_and_rspamd_is_not_an_input(self):
        rows=self.rows();model=m.fit(rows,list(range(8)))
        self.assertTrue(np.all(model[1:]>=0))
        low,high=copy.deepcopy(rows[:2]);high['values'][2]=1.;low['values'][2]=-.8
        self.assertLess(m.predict(model,[low,high],list(range(8)))[0],
                        m.predict(model,[low,high],list(range(8)))[1])
        e=self.evidence();before=m.vector(e)
        e['rspamd']={'score':100,'action':'reject'}
        self.assertEqual(before,m.vector(e))

    def test_protected_campaigns_and_conflicts_are_excluded(self):
        rows=self.rows();reference=copy.deepcopy(rows[0]);reference['id']='f'*64
        kept,excluded=m.campaigns(rows,[reference])
        self.assertEqual(excluded['protected_campaign_messages'],1)
        self.assertNotIn(rows[0]['id'],{r['id'] for r in kept})
        conflicting=copy.deepcopy(rows[1]);conflicting['id']='e'*64;conflicting['spam']=not conflicting['spam']
        kept,excluded=m.campaigns(rows+[conflicting],[])
        self.assertEqual(excluded['conflicting_campaign_messages'],2)

    def test_campaign_out_and_delayed_temporal_labels_are_not_training_truth(self):
        rows=self.rows()
        for row in rows:row['labelled_at']=1000
        seen=[];original=m.fit
        def check(selected,features):
            seen.append({r['id'] for r in selected})
            return original(selected,features)
        with patch.object(m,'fit',side_effect=check):report=m.experiment(rows,[])
        ordered,_=m.campaigns(rows,[])
        for i,row in enumerate(ordered):self.assertNotIn(row['id'],seen[i])
        self.assertEqual(report['variants']['joint']['temporal']['status'],'insufficient_past_labels')
        self.assertFalse(report['may_activate']);self.assertFalse(report['independent_validation'])
        self.assertNotIn('noisefence-quality-model',report['schema'])

    def test_constant_fit_abstains_and_reference_labels_never_fit(self):
        rows=self.rows();reference=copy.deepcopy(rows[0])
        reference.update(id='f'*64,fingerprint='f'*64,campaign='f'*64,simhash='ffffffffffffffff')
        before=m.experiment(rows,[reference]);reference['spam']=not reference['spam']
        after=m.experiment(rows,[reference])
        self.assertEqual(before['variants']['joint']['coefficients'],after['variants']['joint']['coefficients'])
        self.assertEqual(before['variants']['content']['campaign_out']['review'],len(rows))


if __name__=='__main__':unittest.main()
