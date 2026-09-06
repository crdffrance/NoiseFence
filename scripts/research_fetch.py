#!/usr/bin/env python3
"""Fetch documented raw research corpora. No extraction of active attachments."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import urllib.request

BASE = "https://monkey.org/~jose/phishing/"
LIMIT = 64 * 1024 * 1024
SOURCE_LOCK = Path(__file__).resolve().parents[1] / "research" / "sources.lock.json"
PINNED = {item["url"]: item for item in json.loads(SOURCE_LOCK.read_text())} if SOURCE_LOCK.exists() else {}


def fetch(root, name, base=BASE, metadata=None):
    root.mkdir(parents=True, exist_ok=True)
    destination = root / name
    lock = root / (name + ".source.json")
    expected = PINNED.get(base + name)
    local_record = json.loads(lock.read_text()) if lock.exists() else None
    if expected and local_record and expected["sha256"] != local_record["sha256"]:
        raise ValueError("Local source lock differs from the versioned research snapshot")
    expected = expected or local_record
    if not destination.exists():
        temporary = destination.with_suffix(".download")
        try:
            with urllib.request.urlopen(base + name, timeout=45) as response:
                if not response.geturl().startswith(base):
                    raise ValueError("Unexpected corpus redirect")
                with temporary.open("wb") as output:
                    size = 0
                    while chunk := response.read(1024 * 1024):
                        size += len(chunk)
                        if size > LIMIT:
                            raise ValueError("Corpus download exceeds size limit")
                        output.write(chunk)
            digest = hashlib.sha256(temporary.read_bytes()).hexdigest()
            if expected and expected["sha256"] != digest:
                raise ValueError("Upstream corpus changed; preserve the existing research snapshot")
            temporary.replace(destination)
        finally:
            temporary.unlink(missing_ok=True)
    data = destination.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if expected and expected["sha256"] != digest:
        raise ValueError("Local corpus checksum mismatch")
    record = {"url": base + name, "sha256": digest, "bytes": len(data),
              "attribution": "Jose Nazario", "license": "CC-BY-4.0",
              "kind": "metadata" if name.endswith(".txt") else "real_phishing_mbox",
              "external_test": name == "phishing-2025"}
    if metadata:
        record.update(metadata)
    lock.write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record), flush=True)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--enron", action="store_true", help="Fetch original Enron-Spam archives instead")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    names = ["README.txt", "LICENSE.txt"] + [f"phishing-{year}" for year in range(2015, 2026)]
    if args.enron:
        names = [("ham", name) for name in ("beck-s", "farmer-d", "kaminski-v", "kitchen-l", "lokay-m", "williams-w3")]
        names += [("spam", name) for name in ("BG", "GP", "SH")]
        def get(item):
            label, name = item
            return fetch(args.output / label, name + ".tar.gz",
                         f"https://www2.aueb.gr/users/ion/data/enron-spam/raw/{label}/",
                         {"attribution": "Metsis, Androutsopoulos and Paliouras, Enron-Spam, CEAS 2006",
                          "license": "See original Enron-Spam readme; raw mail redistribution not assumed",
                          "kind": "historical_raw_email_archive", "label": label, "external_test": False})
    else:
        def get(name):
            return fetch(args.output, name)
    with ThreadPoolExecutor(max_workers=3) as pool:
        records = list(pool.map(get, names))
    (args.output / "sources.json").write_text(json.dumps(records, indent=2) + "\n")


if __name__ == "__main__":
    main()
