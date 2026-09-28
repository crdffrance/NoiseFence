"""Offline migration safety tests; no production service or external provider calls."""
import hashlib
import json
import os
import pwd
from pathlib import Path
import socket
import sqlite3
import struct
import sys
import tempfile
import threading
import time
import tomllib
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'deploy/postgresql'))
import migration_protocol as protocol
import migration_snapshot as snapshot
import migration_agent as agent
import migrate


def selection():
    return {'protocol': 'noisefence-management-selection-1',
            'database': {'instance': '00000000-0000-4000-8000-000000000001', 'source_digest': 'a'*64},
            'node': {'node': 'mx1', 'epoch': '00000000-0000-4000-8000-000000000002'},
            'role': 'coordinator', 'baseline': {'sequence': 1, 'revision': 1, 'digest': 'b'*64},
            'mfa_key_sha256': 'c'*64}


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.a, self.b = socket.socketpair()
        self.addCleanup(self.a.close)
        self.addCleanup(self.b.close)
        self.channel = protocol.Channel(self.a.fileno(), self.a.fileno(), time.monotonic()+2)

    def frame(self, raw):
        self.b.sendall(struct.pack('!I', len(raw))+raw)

    def test_frames_reject_duplicate_fields_nonfinite_and_nonobjects(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'[]', b'\xff'):
            self.frame(raw)
            with self.assertRaises(ValueError):
                self.channel.receive()
        self.frame(b'{"sequence":2}')
        self.assertEqual(self.channel.receive(), {'sequence': 2})

    def test_oversized_frame_fails_without_reading_payload(self):
        self.b.sendall(struct.pack('!I', protocol.MAX_FRAME+1))
        with self.assertRaises(ValueError):
            self.channel.receive()

    def test_idle_deadline_and_disconnect_are_distinct(self):
        self.channel.deadline = time.monotonic()+0.01
        with self.assertRaises(TimeoutError):
            self.channel.receive()
        self.channel.deadline = time.monotonic()+1
        self.b.close()
        with self.assertRaises(EOFError):
            self.channel.receive()

    def test_checksum_failure_removes_partial_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp).resolve()/'export'
            self.b.sendall(b'wrong')
            with self.assertRaisesRegex(ValueError, 'checksum'):
                self.channel.receive_file(path, {'bytes':5, 'sha256':'0'*64})
            self.assertFalse(path.exists())
            path.write_bytes(b'keep')
            with self.assertRaises(FileExistsError):
                self.channel.receive_file(path, {'bytes':5, 'sha256':'0'*64})
            self.assertEqual(path.read_bytes(), b'keep')

    def test_stream_roundtrip_and_private_permissions(self):
        payload = b'bounded metadata\n'*30000
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            original, received = root/'original', root/'received'
            protocol.atomic(original, payload)
            info = snapshot.describe(original, protocol.MAX_FILE)
            sender = protocol.Channel(self.b.fileno(), self.b.fileno(), time.monotonic()+2)
            errors = []
            def send():
                try:
                    sender.send_file(original, info)
                except BaseException as error:
                    errors.append(error)
            worker = threading.Thread(target=send)
            worker.start()
            self.channel.receive_file(received, info)
            worker.join(2)
            self.assertFalse(worker.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(received.read_bytes(), payload)
            self.assertEqual(received.stat().st_mode & 0o777, 0o600)


class SnapshotTests(unittest.TestCase):
    def test_physical_single_link_files_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = root/'source'
            protocol.atomic(source, b'metadata')
            link = root/'link'
            link.symlink_to(source)
            with self.assertRaises(ValueError):
                protocol.private_read(link, 100)
            link.unlink()
            os.link(source, link)
            with self.assertRaises(ValueError):
                protocol.private_read(source, 100)
            link.unlink()
            source.chmod(0o666)
            with self.assertRaises(ValueError):
                protocol.private_read(source, 100)

    def test_manifest_rejects_bodies_and_path_ambiguity(self):
        base = {n:{'bytes':1, 'sha256':'a'*64} for n in ('state.sqlite3','config.toml')}
        self.assertEqual(snapshot.checked_manifest(base), 2)
        for name in ('messages/message.eml', '../config.toml', '/etc/passwd', 'cluster/models/'+'a'*64+'/../body', 'cluster//credentials/x', 'mfa.key/child'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                snapshot.checked_manifest({**base,name:{'bytes':1,'sha256':'a'*64}})

    def test_backend_append_preserves_settings_and_is_idempotent(self):
        raw = b'data_dir="/var/lib/noisefence"\n[smtp]\nport=25\n[cluster]\nrole="worker"\n'
        desired = {'backend':'coordinator'}
        updated = snapshot.management_config(raw, desired)
        self.assertEqual(tomllib.loads(updated.decode()), {**tomllib.loads(raw.decode()), 'management':desired})
        self.assertEqual(snapshot.management_config(updated, desired), updated)
        with self.assertRaises(ValueError):
            snapshot.management_config(updated, {'backend':'postgresql'})

    def test_config_remap_changes_only_top_level_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            original = {'data_dir':'/original', 'smtp':{'port':25}, 'cluster':{'data_dir':'keep'}}
            protocol.atomic(root/'config.toml', b'data_dir = "/original"\n[smtp]\nport=25\n[cluster]\ndata_dir="keep"\n')
            snapshot.remap_config(root)
            self.assertEqual(tomllib.loads((root/'config.toml').read_text()), {**original, 'data_dir':str(root)})

    def test_selection_rejects_boolean_sequences_and_wrong_mfa_role(self):
        self.assertEqual(protocol.checked_selection(selection()), selection())
        for change in ('sequence', 'mfa', 'node'):
            value = selection()
            if change == 'sequence': value['baseline']['sequence'] = True
            if change == 'mfa': value['role'] = 'worker'
            if change == 'node': value['node']['node'] = '../mx1'
            with self.subTest(change=change), self.assertRaises(ValueError):
                protocol.checked_selection(value)

    def test_export_uses_exact_installed_generation_and_never_mail_bodies(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            data = root/'data'
            data.mkdir()
            config = root/'config.toml'
            protocol.atomic(config, ('data_dir='+json.dumps(str(data))+'\n[cluster]\nnode_id="mx1"\nrole="coordinator"\n').encode())
            files = {'model-0.json':{'sha256':hashlib.sha256(b'model').hexdigest(), 'size':5}}
            digest = hashlib.sha256(protocol.canonical(files)).hexdigest()
            model = data/'cluster'/'models'/digest/'model-0.json'
            model.parent.mkdir(parents=True)
            protocol.atomic(model, b'model')
            credentials = data/'cluster'/'credentials'/('d'*64+'.json')
            credentials.parent.mkdir(parents=True)
            protocol.atomic(credentials, b'{}')
            protocol.atomic(data/'mfa.key', b'k'*32)
            protocol.atomic(data/'message.eml', b'PRIVATE BODY MUST NOT BE EXPORTED')
            export = root/'frozen.sqlite3'
            with sqlite3.connect(export) as db:
                db.execute('CREATE TABLE cluster_state(key TEXT PRIMARY KEY,value TEXT)')
                db.execute('INSERT INTO cluster_state VALUES (?,?)', ('activation_participant', json.dumps({'installed':{'files':files,'credential_generation':'d'*64}})))
            ready = {'export_path':str(export), 'receipt':{**snapshot.describe(export, protocol.MAX_FILE), 'journal':{'identity':selection()['node']}}}
            paths, manifest = snapshot.source_files(data, config, ready)
            self.assertEqual(set(manifest), {'state.sqlite3','config.toml','mfa.key',str(model.relative_to(data)),str(credentials.relative_to(data))})
            self.assertNotIn(data/'message.eml', paths.values())
            self.assertEqual(manifest[str(model.relative_to(data))]['sha256'], hashlib.sha256(b'model').hexdigest())

    def test_format_seven_requires_valid_durable_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            with sqlite3.connect(root/'state.sqlite3') as db:
                db.execute('CREATE TABLE cluster_state(key TEXT PRIMARY KEY,value TEXT)')
                db.execute('PRAGMA user_version=6')
            self.assertIsNone(agent.read_selection(root))
            with sqlite3.connect(root/'state.sqlite3') as db:
                db.execute('PRAGMA user_version=7')
            with self.assertRaises(ValueError): agent.read_selection(root)
            with sqlite3.connect(root/'state.sqlite3') as db:
                db.execute('INSERT INTO cluster_state VALUES (?,?)', ('management_selection', json.dumps(selection())))
            self.assertEqual(agent.read_selection(root), selection())


class RecoveryTests(unittest.TestCase):
    def test_lost_select_ack_keeps_proposal_for_forward_recovery(self):
        subject = agent.Agent.__new__(agent.Agent)
        subject.config = {'role':'coordinator'}
        subject.state = {'phase':'frozen'}
        subject.source = Mock()
        subject.source.ready = {'receipt':{'journal':{'identity':selection()['node']}}}
        subject.source.command.side_effect = EOFError('lost acknowledgement')
        writes = []
        def save(**changes):
            subject.state.update(changes)
            writes.append(dict(subject.state))
        subject.save = save
        with self.assertRaises(EOFError):
            subject.native({'action':'select','selection':selection()})
        self.assertEqual(writes[0]['proposal'], selection())
        self.assertEqual(subject.state['phase'], 'frozen')
        changed = selection()
        changed['database']['source_digest'] = 'd'*64
        with self.assertRaises(ValueError):
            subject.native({'action':'select','selection':changed})
        self.assertEqual(subject.source.command.call_count, 1)

    def test_selected_original_never_cancels_to_legacy(self):
        subject = agent.Agent.__new__(agent.Agent)
        subject.config = {'data':'/fixture'}
        subject.source = None
        with patch.object(agent, 'read_selection', return_value=selection()), patch.object(agent, 'execute') as execute:
            with self.assertRaises(ValueError): subject.cancel()
            execute.assert_not_called()

    def test_coordinator_checks_every_original_before_cancellation(self):
        subject = migrate.Coordinator.__new__(migrate.Coordinator)
        subject.state = {'phase':'selecting'}
        subject.open_peers = Mock()
        first, second = Mock(), Mock()
        first.command.return_value = {'selection':None}
        second.command.return_value = {'selection':selection()}
        subject.peers = {'mx1':first, 'mx2':second}
        with self.assertRaises(ValueError): subject.run(cancel=True)
        first.command.assert_called_once_with('inspect')
        second.command.assert_called_once_with('inspect')

    def test_staging_recovery_requires_database_and_exact_source_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            subject = migrate.Coordinator.__new__(migrate.Coordinator)
            subject.root = Path(tmp).resolve()
            subject.state = {'phase':'importing', 'plan':'/private/import.toml'}
            protocol.atomic(subject.root/'staged.json', protocol.canonical({'database':selection()['database']}))
            subject.program = Mock(side_effect=[{'phase':'copied_not_activated', 'database':selection()['database']}, {'status':'sources_match_inactive_import'}])
            subject.save = Mock()
            subject.recover_staging()
            self.assertEqual(subject.program.call_count, 2)
            self.assertEqual(subject.program.call_args_list[1].args[0][0], 'management-verify-sources')
            subject.save.assert_called_once_with(phase='imported', binding=selection()['database'])
            subject.save.reset_mock()
            subject.program.side_effect = [{'phase':'failed', 'database':selection()['database']}]
            with self.assertRaises(ValueError): subject.recover_staging()
            subject.save.assert_not_called()
            protocol.atomic(subject.root/'staged.json', b'{"database":')
            with self.assertRaises(ValueError): subject.recover_staging()
            subject.save.assert_not_called()

    def test_active_database_finishes_without_collecting_or_reimport(self):
        subject = migrate.Coordinator.__new__(migrate.Coordinator)
        subject.state = {'phase':'selecting','binding':selection()['database']}
        subject.open_peers = Mock()
        subject.status = Mock(return_value={'phase':'active'})
        subject.finish = Mock()
        subject.collect = Mock()
        subject.activate = Mock()
        subject.run()
        subject.finish.assert_called_once_with()
        subject.collect.assert_not_called()
        subject.activate.assert_not_called()



class UnitStateTests(unittest.TestCase):
    def test_missing_unit_differs_from_stopped_loaded_unit(self):
        for load, active, expected in [('not-found','inactive','unknown'),('loaded','inactive','inactive'),('loaded','failed','failed')]:
            result=Mock(returncode=0,stdout=f'LoadState={load}\nActiveState={active}\n'.encode())
            with self.subTest(load=load,active=active), patch.object(agent.subprocess,'run',return_value=result):
                self.assertEqual(agent.unit_state('fixture.service'),expected)

    def test_failed_masked_or_ambiguous_inspection_cannot_authorize_lifecycle(self):
        for code, raw in [(1,b''),(0,b'LoadState=masked\nActiveState=inactive\n'),(0,b'LoadState=loaded\n'),(0,b'LoadState=loaded\nActiveState=active\nActiveState=inactive\n')]:
            with self.subTest(code=code,raw=raw), patch.object(agent.subprocess,'run',return_value=Mock(returncode=code,stdout=raw)):
                with self.assertRaises(ValueError):agent.unit_state('fixture.service')


class ServiceLifecycleTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.units = self.root/'units'
        self.units.mkdir()
        data = self.root/'data'
        data.mkdir(mode=0o700)
        with sqlite3.connect(data/'state.sqlite3') as db:
            db.execute('CREATE TABLE cluster_state(key TEXT PRIMARY KEY,value TEXT)')
            db.execute('PRAGMA user_version=6')
        config = self.root/'config.toml'
        protocol.atomic(config, ('data_dir='+json.dumps(str(data))+'\n[cluster]\nrole="coordinator"\nnode_id="mx1"\n').encode())
        self.original = config.read_bytes()
        current = self.root/'current'
        current.symlink_to('/releases/original')
        self.cfg = {'run_id':'00000000-0000-4000-8000-000000000001', 'node_id':'mx1',
                    'role':'coordinator','user':pwd.getpwuid(os.getuid()).pw_name,
                    'data':str(data), 'config':str(config), 'root':str(self.root/'private'),
                    'runtime':str(self.root/'runtime'), 'current_link':str(current),
                    'release_directory':'/releases/approved',
                    'management':{'backend':'postgresql','connection':{
                        'host':'/run/postgresql','port':5432,'database':'noisefence',
                        'username':'noisefence','max_connections':2}}}
        self.states = {unit:'active' for unit in (*agent.SERVICES, *agent.TIMERS)}
        self.calls = []
        def execute(args, timeout=90):
            self.calls.append(args)
            if args[0] == '/usr/bin/systemctl' and args[1] in ('start','stop'):
                self.states[args[2]] = 'active' if args[1] == 'start' else 'inactive'
            return b''
        # Only root-ownership checks are bypassed: service/file operations remain
        # sandboxed in this fixture, without changing host systemd or its files.
        for patcher in (patch.object(agent,'protected'), patch.object(agent,'UNIT_DIRECTORY',self.units),
                        patch.object(agent,'execute',side_effect=execute),
                        patch.object(agent,'unit_state',side_effect=lambda unit:self.states.get(unit,'unknown'))):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.subject = agent.Agent(self.cfg)

    def select(self):
        selected = selection()
        with sqlite3.connect(Path(self.cfg['data'])/'state.sqlite3') as db:
            db.execute('PRAGMA user_version=7')
            db.execute('INSERT INTO cluster_state VALUES (?,?)', ('management_selection',json.dumps(selected)))
        self.subject.save(phase='selected', proposal=selected)
        return {'phase':'active','activated_at':123,'database':selected['database'],'selections':[selected]}

    def test_crash_between_configuration_and_release_publication_recovers(self):
        self.subject.fence()
        self.assertTrue(self.subject.hold.exists())
        self.assertTrue(all(self.states[u]=='inactive' for u in agent.SERVICES))
        receipt = self.select()
        actual_replace = os.replace
        def interrupt(source, destination):
            if str(destination) == self.cfg['current_link']:
                raise OSError('simulated publication interruption')
            return actual_replace(source, destination)
        with patch.object(agent.os, 'replace', side_effect=interrupt):
            with self.assertRaises(OSError): self.subject.publish(receipt)
        self.assertEqual(self.subject.state['phase'],'publishing')
        self.assertTrue(self.subject.hold.exists())
        self.assertEqual(os.readlink(self.cfg['current_link']), '/releases/original')
        self.assertEqual(self.states['noisefence.service'],'inactive')
        self.subject.close()
        self.subject = agent.Agent(self.cfg)
        actual_lstat = Path.lstat
        def fixture_owner(path):
            info = actual_lstat(path)
            if path.name.startswith('.management-'):
                values = list(info)
                values[4] = 0  # Production runs as root; this fixture does not.
                return os.stat_result(values)
            return info
        with patch.object(Path, 'lstat', fixture_owner):
            self.subject.publish(receipt)
        self.assertEqual(self.subject.state['phase'],'configured')
        self.assertEqual(os.readlink(self.cfg['current_link']), self.cfg['release_directory'])
        self.subject.start()
        self.assertFalse(self.subject.hold.exists())
        self.assertEqual(self.states['noisefence.service'],'active')
        self.assertTrue(all(self.states[u]=='inactive' for u in agent.TIMERS))
        with patch.object(self.subject,'health', return_value={'smtp_ready':True,'service':'active'}):
            self.subject.complete()
        self.assertTrue(all(self.states[u]=='active' for u in agent.TIMERS))
        self.assertEqual(self.subject.state['phase'],'complete')
        updated = tomllib.loads(Path(self.cfg['config']).read_text())
        self.assertEqual(updated, {**tomllib.loads(self.original.decode()), 'management':self.cfg['management']})

    def test_start_skips_reset_for_unloaded_inactive_unit_but_resets_failure(self):
        self.subject.fence()
        self.subject.publish(self.select())
        execute = agent.execute
        def reject_unloaded_reset(args, timeout=90):
            if args[1:3] == ['reset-failed', 'noisefence.service'] and self.states['noisefence.service'] == 'inactive':
                raise ValueError('Unit noisefence.service not loaded')
            return execute(args, timeout=timeout)
        self.calls.clear()
        with patch.object(agent, 'execute', side_effect=reject_unloaded_reset):
            self.subject.start()
        self.assertEqual(self.states['noisefence.service'], 'active')
        self.assertFalse(any('reset-failed' in call for call in self.calls))
        self.states['noisefence.service'] = 'failed'
        self.calls.clear()
        self.subject.start()
        self.assertEqual(self.calls[:2], [
            ['/usr/bin/systemctl', 'reset-failed', 'noisefence.service'],
            ['/usr/bin/systemctl', 'start', 'noisefence.service']])
        self.assertEqual(self.states['noisefence.service'], 'active')

    def test_inactive_receipt_cannot_publish_or_restart_selected_source(self):
        self.subject.fence()
        receipt = self.select()
        receipt['phase'] = 'copied_not_activated'
        with self.assertRaises(ValueError): self.subject.publish(receipt)
        with self.assertRaises(ValueError): self.subject.start()
        with self.assertRaises(ValueError): self.subject.cancel()
        self.assertEqual(Path(self.cfg['config']).read_bytes(),self.original)
        self.assertTrue(self.subject.hold.exists())
        self.assertEqual(self.states['noisefence.service'],'inactive')

    def test_disconnect_keeps_fence_until_explicit_unselected_cancellation(self):
        self.subject.fence()
        self.subject.close()
        self.subject = agent.Agent(self.cfg)
        self.assertTrue(self.subject.hold.exists())
        self.assertEqual(self.states['noisefence.service'],'inactive')
        self.subject.cancel()
        self.assertFalse(self.subject.hold.exists())
        self.assertEqual(self.states['noisefence.service'],'active')
        self.assertTrue(all(self.states[u]=='active' for u in agent.TIMERS))
        self.assertEqual(Path(self.cfg['config']).read_bytes(),self.original)


if __name__ == '__main__':
    unittest.main()
