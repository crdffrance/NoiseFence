#!/usr/bin/env python3
"""Build a private manifest from verified Apache, Enron and Nazario downloads."""
import argparse
from collections import Counter
import hashlib
import json
import mailbox
from pathlib import Path
import tarfile

LIMIT = 2 * 1024 * 1024


def verified(path):
    record = json.loads(path.with_name(path.name + ".source.json").read_text())
    if hashlib.sha256(path.read_bytes()).hexdigest() != record["sha256"]:
        raise ValueError(f"Corpus checksum mismatch: {path}")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("corpus", type=Path)
    a = p.parse_args()
    root = a.corpus.resolve()
    output = root / "research" / "prepared"
    output.mkdir(parents=True, exist_ok=True)
    counts = Counter()
    seen = set()
    with (output / "manifest.jsonl").open("w") as manifest:
        def add(raw, spam, source, year=None, external=False):
            if len(raw) > LIMIT:
                counts["oversized"] += 1
                return
            # Preserve encoded MIME bytes; do not round-trip through Unicode.
            raw = raw.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")
            digest = hashlib.sha256(raw).hexdigest()
            key = (source, spam, digest)
            if key in seen:
                counts["source_exact_duplicates"] += 1
                return
            seen.add(key)
            destination = output / source / (digest + ".eml")
            destination.parent.mkdir(exist_ok=True)
            destination.write_bytes(raw)
            manifest.write(json.dumps({"path": str(destination.relative_to(root)), "spam": spam,
                                       "source": source, "year": year, "external_test": external}) + "\n")
            counts[source] += 1

        for label in ("ham", "spam"):
            for path in sorted((root / "apache" / label).iterdir()):
                if path.is_file():
                    add(path.read_bytes(), label == "spam", "apache-" + label)
        for path in sorted((root / "research" / "enron").glob("*/*.tar.gz")):
            verified(path)
            source = "enron-" + path.name.split(".")[0]
            expanded = 0
            with tarfile.open(path, "r:gz") as archive:
                for index, member in enumerate(archive):
                    if index > 100_000:
                        raise ValueError("Too many archive entries")
                    if not member.isfile() or member.size > LIMIT:
                        continue
                    expanded += member.size
                    if expanded > 1024 * 1024 * 1024:
                        raise ValueError("Expanded archive exceeds budget")
                    # No extractall, symlinks, paths, or executable permissions.
                    add(archive.extractfile(member).read(), path.parent.name == "spam", source)
        for year in range(2015, 2026):
            path = root / "research" / "nazario" / f"phishing-{year}"
            verified(path)
            box = mailbox.mbox(path, create=False)
            try:
                for key in box.iterkeys():
                    add(box.get_bytes(key, from_=False), True, f"nazario-{year}", year, year == 2025)
            finally:
                box.close()
    (output / "preparation.json").write_text(json.dumps(counts, indent=2) + "\n")
    print(json.dumps(counts, indent=2))


if __name__ == "__main__":
    main()
