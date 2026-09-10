"""Absolute local request framing budget, independent of decoder timings."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('vision_framing',
    Path(__file__).resolve().parents[1]/'deploy/vision-worker.py')
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)


class FramingTests(unittest.TestCase):
    def test_fragment_progress_cannot_renew_the_deadline(self):
        conn = Mock()
        conn.recv.side_effect = [b'a', b'b', b'c']
        with patch.object(worker.time, 'monotonic', side_effect=[100, 100.4, 101.01]):
            with self.assertRaises(TimeoutError):
                worker.read_exact(conn, 3, deadline=101)
        self.assertEqual(conn.recv.call_count, 2)
        self.assertAlmostEqual(conn.settimeout.call_args_list[0].args[0], 1)
        self.assertAlmostEqual(conn.settimeout.call_args_list[1].args[0], .6)

    def test_header_and_body_share_one_budget(self):
        conn = Mock()
        conn.recv.side_effect = [b'head', b'body']
        with patch.object(worker.time, 'monotonic', side_effect=[100, 100.9]):
            self.assertEqual(worker.read_exact(conn, 4, 101), b'head')
            self.assertEqual(worker.read_exact(conn, 4, 101), b'body')
        self.assertAlmostEqual(conn.settimeout.call_args_list[1].args[0], .1)

    def test_early_eof_and_legacy_response_read(self):
        conn = Mock()
        conn.recv.side_effect = [b'a', b'']
        with self.assertRaises(EOFError):
            worker.read_exact(conn, 4)
        conn.settimeout.assert_not_called()


if __name__ == '__main__':
    unittest.main()
