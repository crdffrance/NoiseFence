"""Freshness is a necessary condition, never a proof of independent evaluation."""
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'research'))
from quality_exposure import SCHEMA, report, validate


def header():
    return {'since':100,'captured_at':200,'previously_examined':False,
            'exposure_tracking':{'schema':SCHEMA,'tracking_since':99,'candidate_sha256':'a'*64,
                                 'previously_exported':False,'related_campaign_seen':False}}


class ExposureTests(unittest.TestCase):
    def test_first_tracked_export_is_only_eligible_for_further_checks(self):
        value=report(header(),'a'*64)
        self.assertTrue(value['eligible_for_independence_checks'])
        self.assertFalse(value['independent_validation'])
        self.assertFalse(report(header(),'b'*64)['eligible_for_independence_checks'])
        self.assertFalse(report(header())['eligible_for_independence_checks'])

    def test_each_missing_or_reused_provenance_blocks_independence(self):
        for key in ('previously_exported','related_campaign_seen'):
            h=header();h['exposure_tracking'][key]=True
            self.assertFalse(report(h,'a'*64)['eligible_for_independence_checks'])
        h=header();h['since']=99
        self.assertFalse(report(h,'a'*64)['observation_window_covered'])
        h=header();del h['exposure_tracking']
        self.assertFalse(report(h,'a'*64)['eligible_for_independence_checks'])
        for value in (None, True, 0, 'false'):
            h=header();h['previously_examined']=value
            self.assertFalse(report(h,'a'*64)['eligible_for_independence_checks'])

    def test_malformed_present_tracking_is_not_treated_as_legacy(self):
        for key,value in [('tracking_since',True),('tracking_since',201),('tracking_since',0),
                          ('schema','future'),('related_campaign_seen',0),('previously_exported','false')]:
            h=header();h['exposure_tracking'][key]=value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):validate(h)
        for value in (None,{},[],'invalid'):
            h=header();h['exposure_tracking']=value
            with self.assertRaises(ValueError):validate(h)
        h=header();before=copy.deepcopy(h);validate(h)
        self.assertEqual(h,before)


if __name__=='__main__':unittest.main()
