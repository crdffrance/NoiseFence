"""Durable maintenance holds: fault injection, concurrency and exact cancellation."""
import contextlib
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'deploy/postgresql'))
import upgrade_reservation as reservation
import migration_protocol as protocol

OPERATION = '00000000-0000-4000-8000-000000000001'
OTHER = '00000000-0000-4000-8000-000000000002'


class ReservationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.state = self.root / 'state'; self.state.mkdir(mode=0o700)
        self.units = self.root / 'units'; self.units.mkdir()
        self.unit_states = {unit: 'unknown' for unit in reservation.FENCED}
        self.unit_states.update({'noisefence.service': 'active', 'noisefence-train.timer': 'active',
                                 'noisefence-quality.service': 'active'})
        self.events = []
        for name, value in [('STATE', self.state), ('ACTIVE', self.state/'active.json'),
                            ('HOLD', self.state/'hold.json'), ('UNITS', self.units), ('LOCK', self.root/'lock')]:
            p = patch.object(reservation, name, value); p.start(); self.addCleanup(p.stop)
        # Root ownership/systemd startup are exercised separately in disposable Linux.
        for name, value in [('protected', lambda path, directory=False: Path(path).stat()),
                            ('installation', lambda: {'node': 'mx1', 'binary_sha256': 'a'*64}),
                            ('unit_state', lambda unit: self.unit_states.get(unit, 'unknown')), ('execute', self.execute)]:
            p = patch.object(reservation, name, value); p.start(); self.addCleanup(p.stop)
        self.hold = reservation.Reservation(OPERATION)

    def execute(self, args):
        self.events.append(args)
        if args[1] == 'stop':
            # The durable receipt and *all* restart conditions precede stopping.
            self.assertTrue(reservation.ACTIVE.is_file())
            self.assertTrue(reservation.HOLD.is_file())
            for unit in reservation.FENCED:
                text = (self.units/(unit+'.d')/reservation.DROPIN).read_text()
                self.assertEqual(text, '[Unit]\nConditionPathExists=!'+str(reservation.HOLD)+'\n')
            self.unit_states[args[2]] = 'inactive'
        elif args[1] == 'start':
            self.assertFalse(reservation.HOLD.exists())
            self.assertTrue(reservation.ACTIVE.exists())
            self.assertEqual(self.hold.state()['phase'], 'releasing')
            self.unit_states[args[2]] = 'active'
        return b''

    def test_resume_and_cancel_restore_only_previously_active_units(self):
        first = self.hold.begin(); self.assertTrue(first['writers_stopped'])
        created = self.hold.state()['created']
        self.assertEqual(first, self.hold.begin())
        self.assertEqual(self.hold.state()['created'], created)
        self.assertTrue(self.hold.status()['reserved'])
        cancelled = self.hold.cancel(); self.assertEqual(cancelled, self.hold.cancel())
        self.assertFalse(reservation.ACTIVE.exists()); self.assertFalse(reservation.HOLD.exists())
        self.assertEqual([e[2] for e in self.events if e[1] == 'start'],
                         ['noisefence.service', 'noisefence-train.timer'])
        self.assertEqual(self.unit_states['noisefence-quality.service'], 'inactive')
        with self.assertRaisesRegex(ValueError, 'finished'):self.hold.begin()

    def test_lost_connection_during_stop_keeps_hold_and_same_operation_resumes(self):
        actual = self.execute
        def disconnect(args):
            if args[1:3] == ['stop', 'noisefence.service']:raise EOFError('controller disconnected')
            return actual(args)
        with patch.object(reservation, 'execute', disconnect):
            with self.assertRaises(EOFError):self.hold.begin()
        self.assertEqual(self.hold.state()['phase'], 'prepared')
        self.assertTrue(self.hold.status()['service_hold'])
        self.assertFalse(self.hold.status()['writers_stopped'])
        self.assertTrue(self.hold.begin()['writers_stopped'])

    def test_another_operation_and_malformed_marker_are_refused(self):
        self.hold.begin(); before = reservation.ACTIVE.read_bytes()
        with self.assertRaisesRegex(ValueError, 'Another operation'):
            reservation.Reservation(OTHER).begin()
        self.assertEqual(before, reservation.ACTIVE.read_bytes())
        reservation.ACTIVE.write_text('{broken')
        with self.assertRaises(ValueError):self.hold.cancel()
        self.assertTrue(reservation.HOLD.exists())
        self.assertEqual(self.hold.state()['phase'], 'held')

    def test_changed_installation_never_cancels_hold(self):
        self.hold.begin(); self.events.clear()
        with patch.object(reservation, 'installation', return_value={'node': 'mx1', 'binary_sha256': 'b'*64}):
            with self.assertRaisesRegex(ValueError, 'installation changed'):self.hold.cancel()
        self.assertTrue(reservation.HOLD.exists()); self.assertFalse(self.events)

    def test_candidate_marker_or_running_service_prevents_normal_resume(self):
        self.hold.begin(); self.events.clear()
        marker = reservation.STATE / 'validation.json'; marker.write_text('{}')
        with self.assertRaisesRegex(ValueError, 'Stop candidate validation'):self.hold.cancel()
        marker.unlink(); self.unit_states['noisefence-validation.service'] = 'active'
        with self.assertRaisesRegex(ValueError, 'still running'):self.hold.cancel()
        self.assertTrue(reservation.HOLD.exists()); self.assertFalse(self.events)
        self.unit_states['noisefence-validation.service'] = 'inactive'
        self.hold.cancel()

    def test_start_failure_keeps_reservation_until_exact_retry_succeeds(self):
        self.hold.begin()
        actual = self.execute
        def failed_start(args):
            if args[1] == 'start':raise TimeoutError('start timed out')
            return actual(args)
        with patch.object(reservation, 'execute', failed_start):
            with self.assertRaises(TimeoutError):self.hold.cancel()
        self.assertEqual(self.hold.state()['phase'], 'releasing')
        self.assertTrue(reservation.ACTIVE.exists()); self.assertFalse(reservation.HOLD.exists())
        with self.assertRaisesRegex(ValueError, 'releasing'):self.hold.begin()
        self.hold.cancel(); self.assertFalse(reservation.ACTIVE.exists())

    def test_disk_full_before_hold_and_after_stop_never_reports_success(self):
        actual = reservation.atomic
        def full(path, raw, **kwargs):
            if path == reservation.HOLD:raise OSError(errno.ENOSPC, 'full')
            actual(path, raw, **kwargs)
        with patch.object(reservation, 'atomic', full):
            with self.assertRaises(OSError):self.hold.begin()
        self.assertTrue(reservation.ACTIVE.exists())
        self.assertFalse(any(e[1] == 'stop' for e in self.events))
        def receipt_full(path, raw, **kwargs):
            if path == self.hold.path and b'"phase":"held"' in raw:raise OSError(errno.ENOSPC, 'full')
            actual(path, raw, **kwargs)
        with patch.object(reservation, 'atomic', receipt_full):
            with self.assertRaises(OSError):self.hold.begin()
        self.assertTrue(self.hold.status()['writers_stopped'])
        self.assertEqual(self.hold.state()['phase'], 'prepared')
        self.assertTrue(reservation.HOLD.exists())
        self.assertEqual(self.hold.begin()['phase'], 'held')

    def test_failed_terminal_receipt_retains_reservation_and_retries(self):
        self.hold.begin(); actual = reservation.atomic
        def full(path, raw, **kwargs):
            if path == self.hold.path and b'"phase":"cancelled"' in raw:raise OSError(errno.ENOSPC, 'full')
            actual(path, raw, **kwargs)
        with patch.object(reservation, 'atomic', full):
            with self.assertRaises(OSError):self.hold.cancel()
        self.assertTrue(reservation.ACTIVE.exists())
        self.assertEqual(self.hold.state()['phase'], 'releasing')
        self.hold.cancel(); self.assertFalse(reservation.ACTIVE.exists())

    def test_lost_final_acknowledgement_does_not_repeat_start_commands(self):
        self.hold.begin(); actual = reservation.remove
        def lost(path):
            if path == reservation.ACTIVE:raise EOFError('disconnected before final cleanup')
            actual(path)
        with patch.object(reservation, 'remove', lost):
            with self.assertRaises(EOFError):self.hold.cancel()
        self.assertEqual(self.hold.state()['phase'], 'cancelled')
        self.events.clear(); self.hold.cancel()
        self.assertFalse(self.events); self.assertFalse(reservation.ACTIVE.exists())

    def test_orphaned_hold_changed_condition_or_transitioning_unit_refuse(self):
        reservation.HOLD.symlink_to(self.root/'missing')
        with self.assertRaisesRegex(ValueError, 'Orphaned'):self.hold.begin()
        reservation.HOLD.unlink()
        self.unit_states['noisefence-train.timer'] = 'activating'
        with self.assertRaisesRegex(ValueError, 'transitioning'):self.hold.begin()
        self.unit_states['noisefence-train.timer'] = 'active'
        path = self.units/'noisefence.service.d'/reservation.DROPIN
        path.parent.mkdir(); path.write_text('unknown')
        with self.assertRaisesRegex(ValueError, 'condition'):self.hold.begin()
        self.assertFalse(reservation.HOLD.exists())
        self.assertFalse(any(e[1] == 'stop' for e in self.events))

    def test_external_guard_blocks_any_marker_and_io_failures(self):
        marker = self.root/'active'
        with patch.object(protocol, 'UPGRADE_RESERVATION', marker):
            protocol.require_no_upgrade_reservation()
            marker.symlink_to(self.root/'missing')
            with self.assertRaisesRegex(ValueError, 'reservation'):protocol.require_no_upgrade_reservation()
            marker.unlink(); marker.mkdir()
            with self.assertRaisesRegex(ValueError, 'reservation'):protocol.require_no_upgrade_reservation()
            with patch.object(Path, 'lstat', side_effect=PermissionError('denied')):
                with self.assertRaises(PermissionError):protocol.require_no_upgrade_reservation()

    def test_real_advisory_lock_contends_without_waiting(self):
        actual = os.fstat
        def owner(fd):
            info = actual(fd)
            return types.SimpleNamespace(st_mode=info.st_mode, st_uid=0, st_nlink=info.st_nlink,
                                         st_dev=info.st_dev, st_ino=info.st_ino)
        with patch.object(reservation.os, 'fstat', owner):
            with reservation.operation_lock():
                with self.assertRaises(BlockingIOError):
                    with reservation.operation_lock():self.fail('concurrent owner acquired lock')
            with reservation.operation_lock():pass


class InstallationTests(unittest.TestCase):
    def test_exact_release_config_selection_and_manifest_are_bound(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); release = root/'releases/0.31.9'; release.mkdir(parents=True)
            for name in ['noisefence', 'build.json']:(release/name).write_text(name)
            manifest = ''.join(hashlib.sha256((release/n).read_bytes()).hexdigest()+'  '+n+'\n' for n in ['noisefence', 'build.json'])
            (release/'SHA256SUMS').write_text(manifest)
            current = root/'current'; current.symlink_to('releases/0.31.9')
            data = root/'data'; data.mkdir(mode=0o700)
            with contextlib.closing(sqlite3.connect(data/'state.sqlite3')) as db, db:
                db.execute('PRAGMA user_version=6'); db.execute('CREATE TABLE cluster_state(key TEXT, value TEXT)')
            config = root/'config.toml'
            config.write_text('data_dir='+json.dumps(str(data))+'\n[cluster]\nnode_id="mx1"\nrole="coordinator"\n[replication]\n')
            def lstat(path):
                info = original(path)
                if path == current:
                    return types.SimpleNamespace(st_mode=info.st_mode, st_uid=0)
                if path == data:
                    return types.SimpleNamespace(st_mode=info.st_mode, st_uid=os.getuid() or 1)
                return info
            original = Path.lstat
            with patch.object(reservation, 'CONFIG', config), patch.object(reservation, 'CURRENT', current), \
                    patch.object(reservation, 'DATA', data), patch.object(reservation, 'protected', lambda p, directory=False: Path(p).stat()), \
                    patch.object(reservation, 'installed_service', return_value=release/'noisefence'), \
                    patch.object(reservation.pwd, 'getpwnam', return_value=types.SimpleNamespace(pw_uid=os.getuid() or 1)), patch.object(Path, 'lstat', lstat):
                first = reservation.installation()
                self.assertEqual(first['binary_sha256'], hashlib.sha256(b'noisefence').hexdigest())
                config.write_text(config.read_text()+'# changed\n')
                self.assertNotEqual(first, reservation.installation())
                (release/'unexpected').write_text('extra')
                with self.assertRaisesRegex(ValueError, 'Unlisted'):reservation.installation()
                (release/'unexpected').unlink(); (release/'noisefence').write_text('changed')
                with self.assertRaisesRegex(ValueError, 'differs'):reservation.installation()


if __name__ == '__main__':unittest.main()
