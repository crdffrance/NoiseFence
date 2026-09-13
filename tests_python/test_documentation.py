"""Check local documentation links after the English documentation migration."""
from pathlib import Path
import re
import unittest
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


def anchors(path):
    text = path.read_text()
    found = set(re.findall(r'<a\s+id="([^"]+)"', text))
    counts = {}
    for heading in re.findall(r'^#{1,6}\s+(.+)', text, re.M):
        heading = re.sub(r'<[^>]+>', '', heading).lower().strip()
        slug = re.sub(r'[^\w\- ]', '', heading).replace(' ', '-')
        suffix = counts.get(slug, 0)
        counts[slug] = suffix + 1
        found.add(slug + (f'-{suffix}' if suffix else ''))
    return found


class DocumentationLinks(unittest.TestCase):
    def test_local_targets_and_anchors_exist(self):
        failures = []
        files = [*ROOT.glob('*.md'), *ROOT.glob('docs/*.md'), *ROOT.glob('research/*.md'), *ROOT.glob('deploy/**/*.md')]
        for path in files:
            text = re.sub(r'```.*?```', '', path.read_text(), flags=re.S)
            for target in re.findall(r'\]\(([^\s)]+)\)', text):
                url = urlsplit(target.strip('<>'))
                if url.scheme or url.netloc:
                    continue
                destination = (path.parent / unquote(url.path)).resolve() if url.path else path
                label = f'{path.relative_to(ROOT)} → {target}'
                if not destination.exists():
                    failures.append(label + ' (missing file)')
                elif url.fragment and destination.suffix == '.md' and unquote(url.fragment) not in anchors(destination):
                    failures.append(label + ' (missing anchor)')
        self.assertEqual([], failures, '\n'.join(failures))
