"""The public package must be usable by an unprivileged service after extraction."""
import importlib.util
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts'))
spec = importlib.util.spec_from_file_location('package_release', ROOT/'scripts/package_release.py')
package = importlib.util.module_from_spec(spec); spec.loader.exec_module(package)
sys.path.pop(0)


class PackagePermissionsTests(unittest.TestCase):
    def test_host_rehearsal_cannot_claim_bookworm_environment(self):
        metadata = package.build_environment(True)
        self.assertTrue(metadata['rehearsal_only'])
        self.assertIsNone(metadata['minimum_glibc']); self.assertIsNone(metadata['image'])
        metadata = package.build_environment(False)
        self.assertFalse(metadata['rehearsal_only'])
        self.assertEqual(metadata['minimum_glibc'], '2.36')
        self.assertTrue(metadata['image'].startswith('rust@sha256:'))

    def test_private_build_tree_produces_public_readable_archive_without_changing_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original_umask = os.umask(0o077)
            try:
                source = root/'noisefence-0.32.0-rc.1-linux-arm64'; source.mkdir()
                assets = source/'web/assets'; assets.mkdir(parents=True)
                (assets/'index.js').write_bytes(b'console fixture')
                (source/'noisefence').write_bytes(b'binary fixture')
                (source/'noisefence').chmod(0o700)
                paths = [source, *source.rglob('*')]
                before = {p: (stat.S_IMODE(p.stat().st_mode), p.read_bytes() if p.is_file() else None) for p in paths}
                archive = root/'release.tar.gz'
                package.write_archive(source, archive)
            finally:
                os.umask(original_umask)
            with tarfile.open(archive) as tar:
                for member in tar:
                    with self.subTest(name=member.name):
                        self.assertEqual((member.uid, member.gid, member.uname, member.gname), (0, 0, 'root', 'root'))
                        self.assertFalse(member.mode & 0o7022)
                        if member.isdir(): self.assertEqual(member.mode, 0o755)
                        elif member.name.endswith('/noisefence'): self.assertEqual(member.mode, 0o755)
                        else: self.assertEqual(member.mode, 0o644)
            for p, value in before.items():
                self.assertEqual((stat.S_IMODE(p.stat().st_mode), p.read_bytes() if p.is_file() else None), value)

    def test_shared_or_privileged_inputs_cannot_produce_writable_or_setid_members(self):
        for kind, mode, expected in [(tarfile.DIRTYPE, 0o777, 0o755),
                                    (tarfile.REGTYPE, 0o666, 0o644),
                                    (tarfile.REGTYPE, 0o6755, 0o755)]:
            member = tarfile.TarInfo('release/item'); member.type = kind; member.mode = mode
            self.assertEqual(package.archive_metadata(member).mode, expected)

    def test_special_members_are_rejected_instead_of_followed_or_published(self):
        for kind in [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.FIFOTYPE]:
            member = tarfile.TarInfo('release/item'); member.type = kind
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                package.archive_metadata(member)
