import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
spec = importlib.util.spec_from_file_location('release_source', SCRIPTS / 'check_release_source.py')
release_source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release_source)
sys.path.pop(0)


class ReleaseSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git('init', '-b', 'master')
        self.git('commit', '--allow-empty', '-m', 'Reviewed source')
        self.commit = self.git('rev-parse', 'HEAD')
        self.git('tag', '-a', 'v0.1.0', '-m', 'Release')
        self.git('update-ref', 'refs/remotes/origin/master', self.commit)

    def git(self, *args):
        return subprocess.run(
            ['git', '-c', 'user.name=Release test', '-c', 'user.email=test@example.invalid',
             '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false',
             '-c', 'tag.gpgsign=false', *args], cwd=self.root,
            check=True, text=True, capture_output=True).stdout.strip()

    def verify(self, **kwargs):
        args = dict(root=self.root, tag='v0.1.0', default_branch='master', commit=self.commit)
        args.update(kwargs)
        release_source.verify(**args)

    def test_detached_annotated_tag_on_default_branch_is_accepted(self):
        self.git('checkout', '--detach', 'v0.1.0')
        self.verify()

    def test_reviewed_older_tag_is_accepted_after_default_branch_advances(self):
        self.git('commit', '--allow-empty', '-m', 'Later source')
        self.git('update-ref', 'refs/remotes/origin/master', 'HEAD')
        self.git('checkout', '--detach', 'v0.1.0')
        self.verify()

    def test_unmerged_tag_is_refused(self):
        self.git('switch', '-c', 'unreviewed')
        self.git('commit', '--allow-empty', '-m', 'Unreviewed source')
        self.git('tag', 'v0.2.0')
        with self.assertRaises(ValueError):
            self.verify(tag='v0.2.0', commit=self.git('rev-parse', 'HEAD'))

    def test_wrong_checkout_or_moved_tag_is_refused(self):
        self.git('commit', '--allow-empty', '-m', 'Different source')
        with self.assertRaisesRegex(ValueError, 'must match'):
            self.verify()
        self.git('tag', '-f', 'v0.1.0')
        self.git('checkout', '--detach', self.commit)
        with self.assertRaisesRegex(ValueError, 'must match'):
            self.verify()

    def test_missing_default_branch_and_shallow_history_are_refused(self):
        with self.assertRaises(ValueError):
            self.verify(default_branch='missing')
        (self.root / '.git' / 'shallow').write_text(self.commit + '\n')
        with self.assertRaisesRegex(ValueError, 'complete history'):
            self.verify()

    def test_malformed_refs_and_non_full_commits_are_refused(self):
        for kwargs in [dict(tag='--all'), dict(tag='v0.1.0;echo unsafe'),
                       dict(default_branch='../master'), dict(commit=self.commit[:7]),
                       dict(commit='HEAD')]:
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.verify(**kwargs)
