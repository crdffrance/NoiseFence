"""Probe provenance must change with nested Rust, SQL and build inputs."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('probe_manifest', Path(__file__).resolve().parents[1] / 'scripts/probe_manifest.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class ProbeManifestTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.git('init', '-q')
        for name in ('.gitignore', 'Cargo.toml', 'build.rs', 'src/engine.rs',
                     'src/nested/rules.rs', 'src/nested/schema.sql',
                     'examples/pipeline_probe.rs', 'research/quality-protocol.json'):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('var/\n' if name == '.gitignore' else 'synthetic fixture\n')
        self.commit()
        self.output = self.root / 'var/probe'
        self.output.mkdir(parents=True)
        elf = bytearray(64)
        elf[:7] = b'\x7fELF\x02\x01\x01'
        elf[18:20] = (62).to_bytes(2, 'little')
        (self.output / 'pipeline_probe').write_bytes(elf)

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args], stderr=subprocess.PIPE)

    def commit(self):
        self.git('add', '.')
        self.git('-c', 'user.name=Synthetic Fixture', '-c', 'user.email=fixture@example.test',
                 '-c', 'commit.gpgsign=false', 'commit', '-qm', 'Synthetic fixture')

    def test_nested_sources_sql_build_and_protocol_are_bound(self):
        before = probe.source_manifest(self.root)
        for name in ('src/nested/rules.rs', 'src/nested/schema.sql', 'build.rs', 'research/quality-protocol.json'):
            with self.subTest(name=name):
                path = self.root / name
                path.write_text(path.read_text() + 'changed\n')
                with self.assertRaises(ValueError):
                    probe.source_manifest(self.root)
                self.commit()
                after = probe.source_manifest(self.root)
                self.assertNotEqual(before, after)
                self.assertIn(name, {row['path'] for row in after['files']})
                before = after

    def test_new_untracked_input_and_symlink_are_refused(self):
        extra = self.root / 'src/untracked.rs'
        extra.write_text('untracked input\n')
        with self.assertRaises(ValueError):
            probe.source_manifest(self.root)
        extra.unlink()
        (self.root / 'src/link.rs').symlink_to('engine.rs')
        self.commit()
        with self.assertRaises(ValueError):
            probe.source_manifest(self.root)

    def test_complete_artifact_is_reproducible_and_cannot_be_overwritten(self):
        image = 'rust@sha256:' + 'a' * 64
        result = probe.write(self.root, self.output, image)
        data = (self.output / 'sources.json').read_bytes()
        self.assertEqual(probe.hashlib.sha256(data).hexdigest(), result['source_manifest_sha256'])
        self.assertEqual(json.loads(data), probe.source_manifest(self.root))
        self.assertEqual(result['source_file_count'], 8)
        self.assertEqual(result['schema'], 'noisefence-probe-build-2')
        with self.assertRaises(ValueError):
            probe.write(self.root, self.output, image)
        self.assertEqual(data, (self.output / 'sources.json').read_bytes())

    def test_mutable_image_and_wrong_architecture_are_refused(self):
        with self.assertRaises(ValueError):
            probe.write(self.root, self.output, 'rust:latest')
        raw = bytearray((self.output / 'pipeline_probe').read_bytes())
        raw[18:20] = (183).to_bytes(2, 'little')
        (self.output / 'pipeline_probe').write_bytes(raw)
        with self.assertRaises(ValueError):
            probe.write(self.root, self.output, 'rust@sha256:' + 'a' * 64)
        self.assertFalse((self.output / 'build.json').exists())
        self.assertFalse((self.output / 'sources.json').exists())
