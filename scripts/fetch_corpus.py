#!/usr/bin/env python3
"""Download only Apache's public test corpora; never execute or unpack links."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile
import urllib.request

ARCHIVES = {
    "20030228_easy_ham.tar.bz2": "ham",
    "20030228_easy_ham_2.tar.bz2": "ham",
    "20030228_hard_ham.tar.bz2": "ham",
    "20030228_spam.tar.bz2": "spam",
    "20050311_spam_2.tar.bz2": "spam",
}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    manifest = []
    for archive, label in ARCHIVES.items():
        url = "https://spamassassin.apache.org/old/publiccorpus/" + archive
        with urllib.request.urlopen(url, timeout=60) as response:
            payload = response.read(20 * 1024 * 1024 + 1)
        if len(payload) > 20 * 1024 * 1024:
            raise ValueError("Archive exceeds download budget")
        destination = args.output / label
        destination.mkdir(exist_ok=True)
        count, expanded = 0, 0
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:bz2") as tar:
            for member in tar:
                if not member.isfile() or member.size > 2 * 1024 * 1024:
                    continue
                expanded += member.size
                if expanded > 200 * 1024 * 1024:
                    raise ValueError("Expanded archive exceeds budget")
                name = Path(member.name).name
                if not name[:1].isdigit():
                    continue
                body = tar.extractfile(member).read()
                # No extractall: archive paths, links, modes and owner IDs are ignored.
                (destination / (archive.split(".")[0] + "-" + name)).write_bytes(body)
                count += 1
        manifest.append({"url": url, "sha256": hashlib.sha256(payload).hexdigest(), "messages": count})
        print(f"{archive}: {count} {label} messages")
    (args.output / "sources.json").write_text(json.dumps(manifest, indent=2))

if __name__ == "__main__":
    main()
