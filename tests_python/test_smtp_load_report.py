"""Delivery success must not hide incomplete supplementary analysis in load reports."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('smtp_load', Path(__file__).resolve().parents[1] / 'scripts/smtp_load.py')
load = importlib.util.module_from_spec(spec)
spec.loader.exec_module(load)


class LoadReportTests(unittest.TestCase):
    def test_html_limits_remain_visible_with_complete_core(self):
        # Shape observed in the isolated 1 MiB HTML run: no private message content.
        scan = {'complete': True,
                'native_filter': {'report': {'status': 'limited',
                                            'bayes': {'status': 'untrained'},
                                            'fuzzy': {'status': 'not_run'}}},
                'protection': {'local_status': 'limited', 'feed_status': 'not_configured',
                               'campaign_status': 'complete', 'crdf': {'status': 'disabled'},
                               'virustotal': {'status': 'disabled'}, 'url_resolution': None}}
        result = load.component_statuses([scan, scan])
        self.assertEqual(result['native'], {'limited': 2})
        self.assertEqual(result['local_protection'], {'limited': 2})
        self.assertEqual(result['native_bayes'], {'untrained': 2})
        self.assertEqual(result['native_fuzzy'], {'not_run': 2})
        self.assertEqual(result['crdf'], {'disabled': 2})
        self.assertEqual(result['feed'], {'not_configured': 2})
        self.assertEqual(result['campaign'], {'complete': 2})

    def test_missing_null_and_malformed_reports_never_become_complete(self):
        result = load.component_statuses([
            {}, {'semantic': None, 'native_filter': None, 'protection': None},
            {'semantic': {'status': 'complete'}, 'native_filter': {'report': 'broken'},
             'protection': {'local_status': True}},
            {'semantic': {'status': []}, 'native_filter': {'report': {'status': ''}}},
        ])
        self.assertEqual(result['semantic'], {'absent': 2, 'complete': 1, 'invalid': 1})
        self.assertEqual(result['native'], {'absent': 2, 'invalid': 2})
        self.assertEqual(result['local_protection'], {'absent': 3, 'invalid': 1})
        self.assertTrue(all(sum(counts.values()) == 4 for counts in result.values()))

    def test_unknown_status_is_preserved_for_newer_binaries(self):
        result = load.component_statuses([{'llm': {'status': 'new_budget_restriction'}}])
        self.assertEqual(result['llm'], {'new_budget_restriction': 1})
