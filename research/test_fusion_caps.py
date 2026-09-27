"""Numerical contract tests; no mailbox, network or production artifact."""
import copy
import unittest
import numpy as np
from scipy.optimize import approx_fprime
import train_fusion as f


def policy():
    return {'schema': 'noisefence-fusion-family-caps-1',
            'families': {name: {'minimum': -1., 'maximum': 1.} for name in f.FAMILIES}}


class Caps(unittest.TestCase):
    def test_gradient_matches_capped_likelihood_with_saturated_and_zero_families(self):
        caps = policy()
        caps['families']['llm'] = {'minimum': 0., 'maximum': 0.}
        x = np.array([[3., 1., 4.], [-3., .2, 1.], [.2, .1, 1.], [.3, -.5, 2.]])
        y = np.array([1., 0., 1., 0.])
        p = np.array([1., .4, .2, -.2])
        args = (x, y, .7, ['lexical','authentication','llm'], caps)
        _, gradient = f.capped_objective(p, *args)
        numerical = approx_fprime(p, lambda v: f.capped_objective(v,*args)[0], 1e-7)
        np.testing.assert_allclose(gradient,numerical,atol=1e-6)

    def test_joint_family_limit_applies_before_calibration_and_bounds_mitigation(self):
        caps = policy()
        x=np.zeros((2,len(f.PROTOCOL['features'])))
        w=np.zeros(x.shape[1])
        indices=[i for i,v in enumerate(f.PROTOCOL['features']) if v['family']=='authentication'][:2]
        x[0,indices]=1; x[1,indices]=-1; w[indices]=3
        np.testing.assert_allclose(f.combined_logits(x,w,.25,caps),[1.25,-.75])
        np.testing.assert_allclose(f.combined_logits(x,w,.25),[6.25,-5.75])
        caps['families']['authentication']={'minimum':0.,'maximum':0.}
        np.testing.assert_allclose(f.combined_logits(x,w,.25,caps),[.25,.25])

    def test_no_missing_or_malformed_limit_can_default_to_unlimited(self):
        for change in ('missing','unknown','positive_min','negative_max','nan','too_large'):
            caps=copy.deepcopy(policy())
            if change=='missing': del caps['families']['llm']
            elif change=='unknown': caps['families']['other']={'minimum':-1,'maximum':1}
            elif change=='positive_min': caps['families']['llm']['minimum']=1
            elif change=='negative_max': caps['families']['llm']['maximum']=-1
            elif change=='nan': caps['families']['llm']['maximum']=float('nan')
            else: caps['families']['llm']['maximum']=33
            with self.assertRaises(ValueError): f.validate_combination(caps)


if __name__ == '__main__':
    unittest.main()
