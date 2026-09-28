import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('nf_pg_snapshot',ROOT/'deploy/hardening/snapshot.py')
snapshot=importlib.util.module_from_spec(spec);spec.loader.exec_module(snapshot)
def config():return {'cluster':{'role':'coordinator'},'management':{'backend':'postgresql','connection':{'host':'/var/run/postgresql','database':'noisefence','username':'noisefence'}}}
class PostgreSQLBackupTests(unittest.TestCase):
    def test_explicit_local_peer_connection_and_clean_environment(self):
        target=snapshot.postgres_target(config())
        command=snapshot.postgres_command(target,'pg_dump')
        self.assertIn('-i',command);self.assertIn('--host=/var/run/postgresql',command)
        self.assertIn('--no-password',command);self.assertIn('--dbname=noisefence',command)
        self.assertIsNone(snapshot.postgres_target({}))
        self.assertIsNone(snapshot.postgres_target({'cluster':{'role':'worker'},'management':{'backend':'coordinator'}}))
        for key,value in [('host','example.test'),('host','/run/postgresql,example.test'),('database','postgresql://example.test/x'),('username','-root'),('port',True),('password_file','/secret')]:
            cfg=config();cfg['management']['connection'][key]=value
            with self.assertRaises(ValueError):snapshot.postgres_target(cfg)
    def test_partial_dump_is_removed_and_existing_output_is_never_deleted(self):
        target=snapshot.postgres_target(config())
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/'dump'
            output.write_bytes(b'keep')
            with self.assertRaises(FileExistsError):snapshot.dump_postgres(target,output,10)
            self.assertEqual(output.read_bytes(),b'keep');output.unlink()
            def failed(*args,**kwargs):
                kwargs['stdout'].write(b'partial')
                raise subprocess.CalledProcessError(1,['synthetic'])
            with patch.object(snapshot.subprocess,'run',side_effect=failed):
                with self.assertRaises(subprocess.CalledProcessError):snapshot.dump_postgres(target,output,10)
            self.assertFalse(output.exists())
            def success(*args,**kwargs):kwargs['stdout'].write(b'PGDMPsynthetic')
            with patch.object(snapshot.subprocess,'run',side_effect=success):snapshot.dump_postgres(target,output,10)
            self.assertEqual(output.stat().st_mode&0o777,0o600)

class SnapshotWriterTests(unittest.TestCase):
    def test_quality_timer_paused_and_starting_writer_prevents_snapshot(self):
        calls=[]
        def running(*args,**kwargs):
            calls.append(args)
            if args[:3]==('systemctl','is-active','--quiet'):
                return subprocess.CompletedProcess(args,0,'','')
            if args[:2]==('systemctl','is-active'):
                state='activating' if args[2]=='noisefence-quality.service' else 'inactive'
                return subprocess.CompletedProcess(args,3,state+'\n','')
            return subprocess.CompletedProcess(args,0,'','')
        timers=[]
        with patch.object(snapshot,'run',side_effect=running):
            with self.assertRaisesRegex(RuntimeError,'Background writer'):
                snapshot.pause_background_writers(timers)
        self.assertIn('noisefence-quality.timer',timers)
        self.assertIn(('systemctl','stop','noisefence-quality.timer'),calls)
        self.assertEqual(timers,list(snapshot.BACKGROUND_TIMERS))

    def test_manual_worker_lock_blocks_copy_and_releases_daemon_lock_on_failure(self):
        import fcntl,os
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);folder=root/'calibration';folder.mkdir(mode=0o700)
            with (folder/'worker.lock').open('w') as worker:
                os.chmod(folder/'worker.lock',0o600)
                fcntl.flock(worker,fcntl.LOCK_EX|fcntl.LOCK_NB)
                with self.assertRaises(BlockingIOError):
                    with snapshot.writer_locks(root):self.fail('active worker entered copy window')
            with snapshot.writer_locks(root):
                with (root/'daemon.lock').open('r+') as daemon:
                    with self.assertRaises(BlockingIOError):fcntl.flock(daemon,fcntl.LOCK_EX|fcntl.LOCK_NB)
                self.assertEqual((folder/'worker.lock').stat().st_uid,root.stat().st_uid)
            with (root/'daemon.lock').open('r+') as daemon:
                fcntl.flock(daemon,fcntl.LOCK_EX|fcntl.LOCK_NB)

    def test_writer_locks_preserve_owner_and_refuse_redirected_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            with snapshot.writer_locks(root):pass
            self.assertEqual((root/'calibration').stat().st_uid,root.stat().st_uid)
            self.assertEqual((root/'calibration/worker.lock').stat().st_mode&0o777,0o600)
            (root/'daemon.lock').unlink()
            (root/'daemon.lock').symlink_to(root/'calibration/worker.lock')
            with self.assertRaises(OSError):
                with snapshot.writer_locks(root):self.fail('followed symlink')
