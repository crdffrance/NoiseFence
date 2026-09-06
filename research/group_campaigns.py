#!/usr/bin/env python3
"""Remove label conflicts and group canonical/SimHash near-duplicates pre-split.

This is an explicit similarity heuristic, not proof that every campaign was found.
Any group touching an external test source is withheld entirely from fitting.
"""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("input", type=Path)
    p.add_argument("output", type=Path)
    a = p.parse_args()
    records = []
    with a.input.open() as source:
        for line in source:
            item = json.loads(line)
            item.pop("features")
            records.append(item)
    parents = list(range(len(records)))

    def find(i):
        while i != parents[i]:
            parents[i] = parents[parents[i]]
            i = parents[i]
        return i

    def union(a, b):
        a, b = find(a), find(b)
        if a != b:
            parents[max(a, b)] = min(a, b)

    exact, hashes = {}, {}
    buckets = defaultdict(list)
    for i, record in enumerate(records):
        # Feature schemas may tokenize differently; partitions must not depend
        # on their legacy fingerprints when comparing feature families.
        for kind in ("raw_sha256", "campaign"):
            key = (kind, record[kind])
            if key in exact:
                union(i, exact[key])
            exact[key] = i
        value = int(record["simhash"], 16)
        if value in hashes:
            union(i, hashes[value])
            continue
        neighbors = set()
        for band in range(4):
            neighbors.update(buckets[(band, (value >> (16 * band)) & 0xffff)])
        for previous in neighbors:
            if bin(value ^ previous).count("1") <= 3:
                union(i, hashes[previous])
        hashes[value] = i
        for band in range(4):
            buckets[(band, (value >> (16 * band)) & 0xffff)].append(value)
    groups = defaultdict(list)
    for i in range(len(records)):
        groups[find(i)].append(i)
    selected = {}
    stats = Counter(input=len(records), groups=len(groups))
    excluded = []
    for indices in groups.values():
        group = min(records[i]["campaign"] for i in indices)
        if len({records[i]["spam"] for i in indices}) > 1:
            stats["conflicting_groups"] += 1
            stats["conflicting_messages"] += len(indices)
            excluded.append(group)
            continue
        external = [i for i in indices if records[i]["external_test"]]
        choices = external or indices
        representative = min(choices, key=lambda i: records[i]["raw_sha256"])
        selected[representative] = group
        stats["near_or_exact_duplicates_removed"] += len(indices) - 1
        stats["external_campaigns" if external else "internal_campaigns"] += 1
        if external:
            stats["older_messages_withheld_by_external_overlap"] += len(indices) - len(external)
    sources = Counter()
    with a.input.open() as source, a.output.open("w") as output:
        for i, line in enumerate(source):
            if i in selected:
                item = json.loads(line)
                item["fingerprint"] = item["campaign"]
                item["group"] = selected[i]
                output.write(json.dumps(item, separators=(",", ":")) + "\n")
                sources[item["source"]] += 1
    report = {"counts": stats, "sources": sources, "excluded_conflicting_groups": excluded,
              "method": "canonical text with URL/email/number normalization; 64-bit unigram SimHash distance <=3, transitive components; one representative per component",
              "limitation": "Heuristic similarity grouping does not guarantee complete campaign separation."}
    a.output.with_suffix(".groups.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"counts": stats, "sources": sources}, indent=2))


if __name__ == "__main__":
    main()
