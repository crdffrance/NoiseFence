"""Real subprocess/deadline/cleanup checks; no document decoder dependencies."""
import errno
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('vision_process', ROOT/'deploy/vision-worker.py')
worker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(worker)
PIDFD = hasattr(os, 'pidfd_open')


class ProcessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def child(self):
        # Remains alive until the test releases stdin, independent of scheduling.
        process = subprocess.Popen([sys.executable, '-c',
            'import sys; sys.stdin.buffer.read(1); sys.exit(7)'],
            stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.cleanup, process)
        return process

    @staticmethod
    def cleanup(process):
        if process.poll() is None:
            process.kill()
        process.wait(timeout=3)
        if process.stdin is not None:
            process.stdin.close()

    def assert_closed(self, descriptors):
        self.assertEqual(len(descriptors), 1)
        with self.assertRaises(OSError) as error:
            os.fstat(descriptors[0])
        self.assertEqual(error.exception.errno, errno.EBADF)

    @unittest.skipUnless(PIDFD, 'Linux pidfd required; fallback is tested separately')
    def test_exit_notification_reaps_status_and_closes_descriptor(self):
        process = self.child()
        descriptors = []
        original = os.pidfd_open

        def opened(pid):
            fd = original(pid)
            descriptors.append(fd)
            process.stdin.write(b'x')
            process.stdin.flush()
            return fd

        with patch.object(worker.os, 'pidfd_open', side_effect=opened):
            self.assertEqual(worker._wait_process(process, 2), 7)
        self.assertEqual(process.returncode, 7)
        self.assert_closed(descriptors)

    @unittest.skipUnless(PIDFD, 'Linux pidfd required; fallback is tested separately')
    def test_timeout_closes_descriptor_and_leaves_cleanup_to_caller(self):
        process = self.child()
        descriptors = []
        original = os.pidfd_open

        def opened(pid):
            fd = original(pid)
            descriptors.append(fd)
            return fd

        with patch.object(worker.os, 'pidfd_open', side_effect=opened):
            with self.assertRaises(subprocess.TimeoutExpired):
                worker._wait_process(process, .02)
        self.assertIsNone(process.poll())
        self.assert_closed(descriptors)

    @unittest.skipUnless(PIDFD, 'Linux pidfd required')
    def test_poll_failure_closes_descriptor(self):
        process = self.child()
        descriptors = []
        original = os.pidfd_open

        def opened(pid):
            fd = original(pid)
            descriptors.append(fd)
            return fd

        with patch.object(worker.os, 'pidfd_open', side_effect=opened), \
                patch.object(worker.select, 'poll', side_effect=OSError('synthetic poll failure')):
            with self.assertRaises(OSError):
                worker._wait_process(process, 1)
        self.assert_closed(descriptors)

    def test_unavailable_pidfd_preserves_bounded_fallback_and_exit_status(self):
        for error in [AttributeError('not supported'), OSError(errno.ENOSYS, 'not supported'),
                      OSError(errno.EMFILE, 'no descriptors')]:
            with self.subTest(error=type(error).__name__):
                process = self.child()
                original_wait = process.wait

                def release(*, timeout):
                    self.assertGreaterEqual(timeout, 0)
                    self.assertLessEqual(timeout, 1)
                    process.stdin.write(b'x')
                    process.stdin.flush()
                    return original_wait(timeout=timeout)

                with patch.object(worker.os, 'pidfd_open', side_effect=error, create=True) as opened, \
                        patch.object(process, 'wait', side_effect=release) as waited:
                    self.assertEqual(worker._wait_process(process, 1), 7)
                    opened.assert_called_once_with(process.pid)
                    waited.assert_called_once()

    def test_fallback_timeout_does_not_consume_or_reap_running_child(self):
        process = self.child()
        with patch.object(worker.os, 'pidfd_open', side_effect=AttributeError(), create=True):
            with self.assertRaises(subprocess.TimeoutExpired):
                worker._wait_process(process, .02)
        self.assertIsNone(process.poll())

    def test_already_reaped_process_needs_no_descriptor(self):
        process = self.child()
        process.stdin.write(b'x')
        process.stdin.flush()
        self.assertEqual(process.wait(timeout=2), 7)
        with patch.object(worker.os, 'pidfd_open', create=True) as opened:
            self.assertEqual(worker._wait_process(process, 1), 7)
            opened.assert_not_called()

    def command(self, code, **kwargs):
        return worker._file_command([sys.executable, '-c', code], self.root,
                                    time.monotonic()+3, **kwargs)

    def test_file_output_at_limit_and_barcode_no_result_exit(self):
        self.assertEqual(self.command('import sys;sys.stdout.write("x"*16)', maximum=16), b'x'*16)
        self.assertEqual(self.command('import sys;sys.exit(4)', acceptable=(0, 4)), b'')

    def test_decoder_failure_and_output_limits_do_not_expose_stderr(self):
        for code, kwargs, expected in [
            ('import sys;sys.stderr.write("PRIVATE FIXTURE");sys.exit(9)', {}, 'decoder_failed'),
            ('import sys;sys.stdout.write("x"*17)', {'maximum': 16}, 'output_limit'),
            ('import sys;sys.stderr.write("x"*33)', {}, 'output_limit'),
        ]:
            with self.subTest(expected=expected), patch.object(worker, 'MAX_RESPONSE', 32):
                with self.assertRaises(worker.Limited) as error:
                    self.command(code, **kwargs)
                self.assertEqual(str(error.exception), expected)

    def test_decoder_timeout_kills_and_reaps_the_process(self):
        processes = []
        original = subprocess.Popen

        def spawned(*args, **kwargs):
            process = original(*args, **kwargs)
            processes.append(process)
            return process

        with patch.object(worker.subprocess, 'Popen', side_effect=spawned):
            with self.assertRaises(worker.Limited) as error:
                worker._file_command([sys.executable, '-c', 'import time;time.sleep(60)'],
                                     self.root, time.monotonic()+.02)
        self.assertEqual(str(error.exception), 'timeout')
        self.assertEqual(len(processes), 1)
        self.assertEqual(processes[0].returncode, -signal.SIGKILL)

    def test_unexpected_wait_error_also_kills_and_reaps_the_process(self):
        processes = []
        original = subprocess.Popen

        def spawned(*args, **kwargs):
            process = original(*args, **kwargs)
            processes.append(process)
            return process

        with patch.object(worker.subprocess, 'Popen', side_effect=spawned), \
                patch.object(worker, '_wait_process', side_effect=OSError('synthetic failure')):
            with self.assertRaises(OSError):
                self.command('import time;time.sleep(60)')
        self.assertEqual(processes[0].returncode, -signal.SIGKILL)

    @unittest.skipUnless(sys.platform == 'linux', 'Linux /proc verifies descendant termination')
    def test_supervisor_kills_descendants_after_leader_exit_and_timeout(self):
        for timeout in [False, True]:
            with self.subTest(timeout=timeout):
                marker = self.root/('timeout.pid' if timeout else 'exit.pid')
                code = ('import subprocess,sys,time,json,pathlib;'
                        'p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"]);'
                        f'pathlib.Path({str(marker)!r}).write_text(str(p.pid));')
                code += 'time.sleep(60)' if timeout else f'print({json.dumps(worker.result())!r},flush=True)'
                original_popen = subprocess.Popen
                original_wait = worker._wait_process
                leaders = []
                descendants = []

                def spawned(_args, **kwargs):
                    p = original_popen([sys.executable, '-c', code], **kwargs)
                    leaders.append(p)
                    self.addCleanup(self.cleanup, p)
                    return p

                def ready(process, budget):
                    self.assertEqual(budget, 4.5)
                    end = time.monotonic()+3
                    while True:
                        try:
                            value = marker.read_text()
                        except FileNotFoundError:
                            value = ''
                        if value.isdecimal():
                            break
                        if time.monotonic() >= end:
                            self.fail('synthetic job did not create its descendant')
                        time.sleep(.01)
                    pid = int(value)
                    descendants.append(pid)
                    self.assertEqual(os.getpgid(pid), process.pid)
                    return original_wait(process, .02 if timeout else 2)

                try:
                    with patch.object(worker.subprocess, 'Popen', side_effect=spawned), \
                            patch.object(worker, '_wait_process', side_effect=ready):
                        result = json.loads(worker.supervise(b'{}', 'synthetic-backend'))
                    self.assertEqual(result['status'], 'limited' if timeout else 'complete')
                    if timeout:
                        self.assertEqual(result['errors'], ['worker_limit'])
                        self.assertEqual(leaders[0].returncode, -signal.SIGKILL)
                    else:
                        self.assertEqual(leaders[0].returncode, 0)
                    end = time.monotonic()+3
                    while True:
                        try:
                            state = Path(f'/proc/{descendants[0]}/stat').read_text().rsplit(') ', 1)[1].split()[0]
                        except (FileNotFoundError, ProcessLookupError):
                            # Linux can return ESRCH from read() when the task
                            # disappears after /proc/PID/stat was opened.
                            break
                        if state == 'Z':
                            break  # terminated; its new parent owns reaping
                        if time.monotonic() >= end:
                            self.fail('decoder descendant is still running')
                        time.sleep(.01)
                finally:
                    for leader in leaders:
                        try:
                            os.killpg(leader.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass


if __name__ == '__main__':
    unittest.main(verbosity=2)
