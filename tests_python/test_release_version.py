"""Release candidates share identity and ordering rules across artifact workflows."""
import copy
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'deploy/postgresql'))
import release_version as versions
import release_bundle
import upgrade_validation
sys.path.pop(0)
from tests_python import test_upgrade_validation as validation_fixtures
from tests_python import test_release_bundle as bundle_fixtures
sys.path.insert(0,str(ROOT/'scripts'))
import version as manifests
sys.path.pop(0)


class ReleaseVersionTests(unittest.TestCase):
    def test_semver_order_includes_numeric_identifiers_and_final_release(self):
        ordered=['1.0.0-alpha','1.0.0-alpha.1','1.0.0-alpha.beta','1.0.0-beta',
                 '1.0.0-beta.2','1.0.0-beta.11','1.0.0-rc.1','1.0.0','1.0.1-rc.1','1.0.1','1.1.0']
        self.assertEqual(sorted(reversed(ordered),key=versions.precedence),ordered)
        self.assertLess(versions.precedence('0.31.9'),versions.precedence('0.32.0-rc.1'))
        self.assertLess(versions.precedence('1.0.0-9'),versions.precedence('1.0.0-A'))
        self.assertLess(versions.precedence('1.0.0-A'),versions.precedence('1.0.0-a'))

    def test_supported_subset_is_bounded_and_excludes_ambiguous_versions(self):
        for value in ['0.0.0','1.0.0','0.32.0-rc.1','1.0.0-x-y-z.--','1.0.0-01alpha','1.0.0-0']:
            self.assertTrue(versions.valid(value),value)
        for value in ['',None,False,1,'1.0','v1.0.0','01.0.0','1.0.0-01','1.0.0-rc..1',
                      '1.0.0-rc.01','1.0.0-','1.0.0+build.1','1.0.0/../../x','1.0.0-α',
                      '1.0.0\n','1.0.0-'+('a'*64)]:
            self.assertFalse(versions.valid(value),repr(value))
            with self.assertRaises(ValueError):versions.precedence(value)

    def test_manifest_and_staging_require_the_same_candidate_identity(self):
        for value in ['0.31.9','0.32.0-rc.1','1.0.0-x-y-z.--']:
            self.assertIsNotNone(re.fullmatch(manifests.SEMVER,value))
            self.assertEqual(release_bundle.identity(value,'linux-arm64','a'*40),f'noisefence-{value}-linux-arm64')
        for value in ['1.0.0-rc.01','1.0.0+other','1.0.0-..']:
            self.assertIsNone(re.fullmatch(manifests.SEMVER,value))
            with self.assertRaises(ValueError):release_bundle.identity(value,'linux-arm64','a'*40)

    def test_cargo_metadata_is_checked_before_packaging(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            with patch.object(manifests,'ROOT',root):
                for value in ['0.32.0-rc.1','0.32.0-rc.01']:
                    (root/'Cargo.toml').write_text('version = "'+value+'"\n')
                    if versions.valid(value):self.assertEqual(manifests.cargo_version(),value)
                    else:
                        with self.assertRaises(SystemExit):manifests.cargo_version()

    def test_native_descriptors_accept_rc_but_keep_exact_pair_version_binding(self):
        own=validation_fixtures.descriptor();peer=validation_fixtures.descriptor('mx2')
        peer['expires_at']=own['expires_at']
        for value in ['0.32.0-rc.1','1.0.0','1.0.0-alpha.3']:
            own['candidate']['version']=peer['candidate']['version']=value
            upgrade_validation.authorize(own,peer)
            other=copy.deepcopy(peer);other['candidate']['version']=value+'a'
            with self.assertRaises(ValueError):upgrade_validation.authorize(own,other)
        for value in ['0.32.0-rc.01','1.0.0+rebuild','1.0.0-α']:
            own['candidate']['version']=value
            with self.assertRaises(ValueError):upgrade_validation.checked_descriptor(own)

    def test_prerelease_bundle_is_inspected_and_extracted_with_exact_metadata(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);version='0.32.0-rc.1';top='noisefence-'+version+'-linux-arm64'
            archive=root/(top+'.tar.gz')
            with patch.object(bundle_fixtures,'VERSION',version),patch.object(bundle_fixtures,'TOP',top):
                bundle_fixtures.fixture(archive)
            result=release_bundle.inspect_archive(archive,version,'linux-arm64','a'*40,destination=root/'staged')
            self.assertEqual(result['version'],version)
            self.assertIn('web/index.html',result['files'])
            with self.assertRaises(ValueError):release_bundle.inspect_archive(archive,'0.32.0','linux-arm64','a'*40)
