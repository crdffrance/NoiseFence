#!/usr/bin/env python3
"""Fit sparse linear models; select on development, calibrate, then evaluate once.

Consumes Rust-extracted features. Exports JSON weights, never executable pickles.
The test metrics do not select the algorithm, hyperparameters, or operating point.
"""
import argparse
from array import array
import hashlib
import json
import math
from pathlib import Path
import time

import numpy as np
from scipy import sparse
from sklearn.feature_extraction.text import TfidfTransformer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score


def wilson(k, n):
    if not n:
        return [0.0, 1.0]
    z = 1.959963984540054
    p = k / n
    denominator = 1 + z * z / n
    center = (p + z * z / (2 * n)) / denominator
    half = z * math.sqrt((p * (1 - p) + z * z / (4 * n)) / n) / denominator
    return [max(0, center - half), min(1, center + half)]


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as source:
        while chunk := source.read(1024 * 1024):
            result.update(chunk)
    return result.hexdigest()


def cutoff(labels, logits, target=0.001):
    ham = np.sort(np.asarray(logits)[~labels])[::-1]
    if not len(ham):
        raise ValueError("Calibration requires legitimate messages")
    allowed = int(len(ham) * target)
    # Leave a numerical margin between the last excluded ham and the decision
    # boundary; Rust and BLAS sum sparse dot products in different orders.
    return float(ham[min(allowed, len(ham) - 1)] + 1e-6)


def metrics(labels, logits, threshold):
    predicted = logits >= threshold
    ham, spam = int((~labels).sum()), int(labels.sum())
    tp, fp = int((predicted & labels).sum()), int((predicted & ~labels).sum())
    return {"ham": ham, "spam": spam, "true_positive": tp, "false_positive": fp,
            "recall": tp / spam if spam else None, "precision": tp / (tp + fp) if tp + fp else None,
            "false_positive_rate": fp / ham if ham else None,
            "recall_ci95": wilson(tp, spam), "fpr_ci95": wilson(fp, ham),
            "average_precision": float(average_precision_score(labels, logits)) if spam and ham else None,
            "roc_auc": float(roc_auc_score(labels, logits)) if spam and ham else None}


def load(path, dimension):
    columns, values, indptr, examples = array('i'), array('d'), array('i', [0]), []
    seen = {}
    with path.open() as source:
        for line in source:
            item = json.loads(line)
            key = item["fingerprint"]
            if not isinstance(item["spam"], bool) or len(key) != 64 or any(c not in '0123456789abcdef' for c in key):
                raise ValueError("Invalid label or fingerprint")
            if key in seen:
                if seen[key] != item["spam"]:
                    raise ValueError("Conflicting labels must be removed before training")
                raise ValueError("Duplicate fingerprints must be grouped before training")
            seen[key] = item["spam"]
            pairs = item["features"]
            if len(pairs) > dimension or len({i for i, _ in pairs}) != len(pairs):
                raise ValueError("Invalid feature vector")
            for i, value in pairs:
                if not 0 <= i < dimension or not math.isfinite(value) or not 0 <= value <= 1:
                    raise ValueError("Invalid feature index/value")
                columns.append(i)
                values.append(value)
            indptr.append(len(values))
            examples.append({k: v for k, v in item.items() if k != "features"})
    matrix = sparse.csr_matrix((np.asarray(values), np.asarray(columns), np.asarray(indptr)), shape=(len(examples), dimension))
    return matrix, examples


def partition(examples):
    names = []
    for item in examples:
        # The importer supplies a near-duplicate campaign group when available.
        group = item.get("group", item["fingerprint"])
        bucket = int(hashlib.sha256(group.encode()).hexdigest()[:8], 16) % 10
        names.append("external" if item.get("external_test") else
                     "test" if bucket < 2 else "calibration" if bucket == 2 else
                     "development" if bucket == 3 else "train")
    names = np.array(names)
    return {name: np.flatnonzero(names == name) for name in
            ("train", "development", "calibration", "test", "external")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--dimension", type=int, default=16384)
    parser.add_argument("--feature-version", type=int, default=1)
    parser.add_argument("--development-only", action="store_true",
                        help="Select within this feature family without opening calibration/test metrics")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    matrix, examples = load(args.input, args.dimension)
    if any(e.get("feature_version", 1) != args.feature_version for e in examples):
        raise ValueError("Mixed or incompatible feature schemas")
    labels = np.array([e["spam"] for e in examples], dtype=bool)
    partitions = partition(examples)
    for name in ("train", "development", "calibration", "test"):
        if set(labels[partitions[name]]) != {False, True}:
            raise ValueError(f"{name} needs both classes")
    # No preprocessing is fitted on development, calibration, or test.
    transformer = TfidfTransformer()
    transformer.fit(matrix[partitions["train"]])
    matrix = transformer.transform(matrix)
    train, dev, cal, test = (partitions[n] for n in ("train", "development", "calibration", "test"))
    x, y = matrix[train], labels[train]
    binary = x.copy()
    binary.data[:] = 1
    positive = np.asarray(binary[y].sum(axis=0)).ravel() + 1
    negative = np.asarray(binary[~y].sum(axis=0)).ravel() + 1
    ratio = np.log((positive / positive.sum()) / (negative / negative.sum()))
    choices = []
    best = None
    for family in ("tfidf_logistic", "nb_logistic"):
        scaling = np.ones(args.dimension) if family == "tfidf_logistic" else ratio
        training = x.multiply(scaling).tocsr()
        for c in (0.1, 1.0, 10.0, 100.0):
            started = time.monotonic()
            estimator = LogisticRegression(C=c, solver="liblinear", max_iter=2000,
                                           tol=1e-6, random_state=20260906)
            estimator.fit(training, y)
            weights = estimator.coef_[0] * scaling
            bias = float(estimator.intercept_[0])
            logits = np.asarray(matrix[dev] @ weights).ravel() + bias
            evaluation = metrics(labels[dev], logits, cutoff(labels[dev], logits))
            result = {"family": family, "C": c, "development": evaluation,
                      "fit_seconds": round(time.monotonic() - started, 3),
                      "iterations": estimator.n_iter_.tolist()}
            choices.append(result)
            print(json.dumps(result), flush=True)
            ranking = (evaluation["recall"], evaluation["average_precision"])
            if best is None or ranking > best[0]:
                best = (ranking, result, weights, bias)
    _, chosen, weights, bias = best
    if args.development_only:
        now = int(time.time())
        model = {"version": f"research-{chosen['family'].replace('_','-')}-{now}",
                 "algorithm": "logistic", "feature_version": args.feature_version,
                 "bias": bias, "weights": weights.tolist(), "idf": transformer.idf_.tolist(),
                 "trained_at": now, "examples": len(train)}
        payload = json.dumps(model, separators=(",", ":"), allow_nan=False).encode()
        (args.output / "raw-model.json").write_bytes(payload)
        report = {"selected": chosen, "candidates": choices, "feature_version": args.feature_version,
                  "dimension": args.dimension, "input": str(args.input.resolve()),
                  "corpus_sha256": digest(args.input), "model_sha256": hashlib.sha256(payload).hexdigest(),
                  "selection_metrics_scope": "development only; calibration and test not evaluated",
                  "split_counts": {k: len(v) for k, v in partitions.items()}}
        (args.output / "development.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"selected": chosen, "test_evaluated": False}), flush=True)
        return
    raw_logits = np.asarray(matrix @ weights).ravel() + bias
    operating_point = cutoff(labels[cal], raw_logits[cal])
    # Match the configured suspicion index, not a calibrated spam probability.
    exported_bias = bias + math.log(0.95 / 0.05) - operating_point
    now = int(time.time())
    model = {"version": f"research-{chosen['family'].replace('_','-')}-{now}",
             "algorithm": "logistic", "feature_version": args.feature_version,
             "bias": exported_bias, "weights": weights.tolist(), "idf": transformer.idf_.tolist(),
             "trained_at": now, "examples": len(train)}
    payload = json.dumps(model, separators=(",", ":"), allow_nan=False).encode()
    (args.output / "model.json").write_bytes(payload)
    results = {name: metrics(labels[indices], raw_logits[indices], operating_point)
               for name, indices in partitions.items() if len(indices)}
    by_source = {}
    for name in ("test", "external"):
        for source in sorted({examples[i].get("source", "unspecified") for i in partitions[name]}):
            indices = np.array([i for i in partitions[name] if examples[i].get("source", "unspecified") == source])
            by_source[name + ":" + source] = metrics(labels[indices], raw_logits[indices], operating_point)
    report = {"model_sha256": hashlib.sha256(payload).hexdigest(),
              "corpus_sha256": digest(args.input),
              "feature_version": args.feature_version, "dimension": args.dimension,
              "created": now, "selected": chosen, "candidates": choices,
              "operating_point_raw_logit": operating_point, "threshold": 95.0,
              "split": "group hash: train60/dev10/calibration10/test20; external sources excluded from fitting",
              "partitions": results, "by_source": by_source, "eligible": False,
              "limitation": "Research only. Historical/one-source data does not validate recent production quality. Live authentication, reputation and LLM fusion require separate evaluation."}
    (args.output / "report.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    with (args.output / "predictions.jsonl").open("w") as stream:
        for name, indices in partitions.items():
            if name == "train":
                continue
            for i in indices:
                stream.write(json.dumps({"fingerprint": examples[i]["fingerprint"],
                                         "partition": name, "spam": bool(labels[i]),
                                         "logit": float(raw_logits[i]),
                                         "predicted_spam": bool(raw_logits[i] >= operating_point)}) + "\n")
    print(json.dumps({"selected": chosen, "partitions": results, "eligible": False}), flush=True)


if __name__ == "__main__":
    main()
