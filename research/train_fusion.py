#!/usr/bin/env python3
"""Fit, freeze, then evaluate a private native fusion candidate. No activation.

Inputs are the Rust fusion-export contract and explicit human annotations. No
content, DNS, cloud inference or executable model serialization is used here.
"""
import argparse
from collections import Counter, defaultdict, namedtuple
import hashlib
import json
import math
import os
from pathlib import Path
import warnings

import numpy as np
from scipy.optimize import minimize
from scipy.special import expit
from sklearn.exceptions import ConvergenceWarning
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

PROTOCOL_BYTES = Path(__file__).with_name('fusion-protocol.json').read_bytes()
PROTOCOL = json.loads(PROTOCOL_BYTES)
PROTOCOL_HASH = hashlib.sha256(PROTOCOL_BYTES).hexdigest()
SPLITS = ('train', 'development', 'calibration', 'threshold', 'test')
BASE_USES = ['fit', 'development', 'calibration', 'threshold', 'previous_tests']
FAMILIES = ('lexical', 'semantic', 'authentication', 'smtp_policy',
            'reputation', 'antivirus', 'signatures', 'llm')
VARIANTS = {'content': FAMILIES[:2], 'identity': FAMILIES[:4],
            'reputation': FAMILIES[:5], 'scanners': FAMILIES[:7], 'full': FAMILIES}
# Frozen, repository-owned protocols only. A manifest cannot choose a path or
# change process-global feature configuration while another experiment runs.
KNOWN_PROTOCOLS = (
    ('8cf131ff25a263dae4c921297b371c9c51f5c3c89eeda77ec0a4140f79d835ce', 'fusion-protocol.json', 1),
    ('01d3cefd82f9275b07f407a8d56cf56f8552070e92f78995350664cf05ba1ad6', 'fusion-protocol-2.json', 2),
)
LOCAL_STATES = ('missing', 'disabled', 'complete', 'busy', 'partial', 'invalid', 'unavailable')
# Same fixed order/caps as the native media projection. Raw counts remain
# integers; log scaling avoids enormous unscaled coefficients for tiny media.
MEDIA_LOG_FEATURES = (
    ('structure.image_max_width_log16384', 16_384),
    ('structure.image_max_height_log16384', 16_384),
    ('structure.image_max_pixels_log100000000', 100_000_000),
    ('structure.image_bytes_log16777216', 16_777_216),
    ('structure.pdf_bytes_log16777216', 16_777_216),
)
# Order matches content_inspection::Settings serialization, not JSON input order.
STRUCTURE_LIMITS = (
    ('max_raw_bytes', 16 * 1024 * 1024), ('max_parts', 256), ('max_mime_depth', 16),
    ('max_header_bytes', 64 * 1024), ('max_part_bytes', 8 * 1024 * 1024),
    ('max_total_decoded_bytes', 16 * 1024 * 1024), ('max_html_bytes', 512 * 1024),
    ('max_archive_entries', 1024), ('max_unpacked_bytes', 8 * 1024 * 1024),
    ('max_total_unpacked_bytes', 32 * 1024 * 1024), ('max_compression_ratio', 200),
    ('max_structure_nodes', 100_000), ('max_nesting', 64), ('max_findings', 512),
    ('max_image_pixels', 100_000_000), ('max_images', 256),
)
Feature = namedtuple('Feature', 'name family minimum maximum')


class Protocol(namedtuple('Protocol', 'sha256 version features variants')):
    __slots__ = ()

    @property
    def model_schema(self):
        return 'noisefence-fusion-model-' + str(self.version)

    @property
    def variant_names(self):
        return tuple(name for name, _ in self.variants)


ExperimentContext = namedtuple('ExperimentContext', 'protocol local_binding')
GRID = (.1, 1., 10.)
TARGET_FPR = .001
MAX_ROWS = 50_000
MAX_BYTES = 512 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def is_hex(value, length=64):
    return isinstance(value, str) and len(value) == length and all(c in '0123456789abcdef' for c in value)


def numeric(value):
    return type(value) in (int, float) and math.isfinite(value)


def token(value):
    return isinstance(value, str) and 0 < len(value) <= 128 and all(c.isascii() and (c.isalnum() or c in '._-') for c in value)


def decode(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Non-finite JSON')))


def bound_bytes(path, maximum):
    with path.open('rb') as source:
        raw = source.read(maximum + 1)
    require(len(raw) <= maximum, 'Oversized input')
    return raw


def protocol_for_hash(digest):
    entry = next((entry for entry in KNOWN_PROTOCOLS if entry[0] == digest), None)
    require(entry is not None, 'Unknown fusion protocol hash')
    expected, filename, version = entry
    raw = bound_bytes(Path(__file__).with_name(filename), 128 * 1024)
    require(hashlib.sha256(raw).hexdigest() == expected, 'Bundled fusion protocol changed')
    data = decode(raw)
    require(data['schema'] == 'noisefence-fusion-features-' + str(version)
            and data['evidence_schema'] == 'noisefence-evidence-1', 'Invalid bundled protocol schema')
    features = tuple(Feature(**feature) for feature in data['features'])
    if version == 1:
        variants = tuple(VARIANTS.items())
    else:
        base = protocol_for_hash(KNOWN_PROTOCOLS[0][0])
        require(len(features) > 218 and features[:218] == base.features
                and {f.family for f in features[218:]} == {'heuristics', 'structure'},
                'V2 must append the fixed local catalog to the frozen 218 features')
        variants = (('baseline', FAMILIES), ('heuristics', FAMILIES + ('heuristics',)),
                    ('structure', FAMILIES + ('structure',)), ('full', FAMILIES + ('heuristics', 'structure')))
    return Protocol(expected, version, features, variants)


def validate_local_binding(binding):
    require(isinstance(binding, dict) and set(binding) == {'version', 'heuristics', 'structure'}
            and binding['version'] == 'noisefence-local-evidence-1', 'Invalid local binding')
    heuristic = binding['heuristics']
    if heuristic is not None:
        require(isinstance(heuristic, dict) and set(heuristic) == {
                'version', 'pattern_version', 'settings_digest', 'enabled', 'rule_ids'}
                and heuristic['version'] == 'heuristics-1' and heuristic['pattern_version'] == 'heuristics-fr-en-1'
                and is_hex(heuristic['settings_digest']) and type(heuristic['enabled']) is bool
                and isinstance(heuristic['rule_ids'], list) and len(heuristic['rule_ids']) <= 64
                and all(token(r) and len(r) <= 64 for r in heuristic['rule_ids'])
                and heuristic['rule_ids'] == sorted(set(heuristic['rule_ids'])), 'Invalid heuristic binding/catalog')
    structure = binding['structure']
    if structure is not None:
        require(isinstance(structure, dict) and set(structure) == {'version', 'settings_digest', 'limits'}
                and structure['version'] == 'noisefence-content-inspection-1'
                and is_hex(structure['settings_digest']), 'Invalid structure binding')
        limits = structure['limits']
        require(isinstance(limits, dict) and set(limits) == {k for k, _ in STRUCTURE_LIMITS}
                and all(type(limits[k]) is int and 1 <= limits[k] <= ceiling for k, ceiling in STRUCTURE_LIMITS)
                and limits['max_part_bytes'] <= limits['max_total_decoded_bytes']
                and limits['max_unpacked_bytes'] <= limits['max_total_unpacked_bytes'], 'Invalid structure limits')
        ordered = {key: limits[key] for key, _ in STRUCTURE_LIMITS}
        raw = json.dumps([structure['version'], ordered], separators=(',', ':'), ensure_ascii=False).encode()
        require(hashlib.sha256(raw).hexdigest() == structure['settings_digest'], 'Structure binding digest mismatch')


def vector_context(header, protocol):
    fields = {'type', 'schema', 'protocol_sha256', 'artifacts'}
    if protocol.version == 2:
        fields.add('local_binding')
    require(isinstance(header, dict) and set(header) == fields
            and header['type'] == 'header' and header['schema'] == 'noisefence-fusion-vectors-1'
            and header['protocol_sha256'] == protocol.sha256, 'Invalid Rust vector protocol')
    binding = header.get('local_binding')
    if protocol.version == 2:
        validate_local_binding(binding)
    return ExperimentContext(protocol, binding)


def log_scaled_integer(value, cap):
    if not numeric(value) or not 0 <= value <= 1:
        return False
    raw = math.expm1(value * math.log1p(cap))
    # Inverting ln1p can amplify float rounding near the cap. Keep an absolute
    # floor plus a few ULPs, rather than accepting a relative fraction of a count.
    tolerance = max(1e-7, 32 * math.ulp(raw))
    return math.isclose(raw, round(raw), rel_tol=0., abs_tol=tolerance)


def validate_local_vector(row, context):
    if context.protocol.version != 2:
        return
    values = {feature.name: value for feature, value in zip(context.protocol.features, row['values'])}
    states = {}
    for family in ('heuristics', 'structure'):
        flags = [values[family + '.state.' + state] for state in LOCAL_STATES]
        require(all(v in (0, 1) for v in flags) and sum(flags) == 1, 'Invalid local availability vector')
        states[family] = LOCAL_STATES[flags.index(1)]
    profile = row['availability_profile'].split('/')
    require(len(profile) == 14 and profile[-2:] == [states['heuristics'], states['structure']],
            'Availability profile differs from encoded local states')
    heuristic = context.local_binding['heuristics']
    enabled = heuristic is not None and heuristic['enabled']
    require(enabled != (states['heuristics'] == 'disabled')
            and (context.local_binding['structure'] is not None) != (states['structure'] == 'disabled'),
            'Local availability contradicts binding')
    hits = [values[f'heuristics.rule_{i:02}.hit'] for i in range(64)]
    used = len(heuristic['rule_ids']) if heuristic is not None else 0
    require(all(v in (0, 1) for v in hits) and not any(hits[used:])
            and (states['heuristics'] == 'complete' or not any(hits)), 'Invalid local heuristic vector')
    finding_names = ('html_active_element', 'html_event_handler', 'html_active_url', 'pdf_active_name',
                     'office_vba_project', 'office_xlm_macros', 'office_external_relationship',
                     'office_embedded_object', 'type_mismatch', 'image_dimensions', 'image_count',
                     'html_refresh', 'html_embedded_content', 'pdf_external_reference', 'office_macro_enabled')
    scaled_counts = [(feature.name, int(feature.name.rsplit('_div', 1)[1]))
                     for feature in context.protocol.features
                     if feature.family == 'structure' and '_div' in feature.name]
    structure = [values[f.name] for f in context.protocol.features if f.family == 'structure'
                 and not f.name.startswith('structure.state.')]
    require(all(values['structure.' + name] in (0, 1) for name in finding_names)
            and all(math.isclose(values[name] * scale, round(values[name] * scale), rel_tol=0., abs_tol=1e-7)
                    for name, scale in scaled_counts)
            and all(log_scaled_integer(values[name], cap) for name, cap in MEDIA_LOG_FEATURES)
            and (states['structure'] == 'complete' or not any(structure)), 'Invalid local structure vector')
    require(not row['tag_eligible'] or all(s in ('disabled', 'complete') for s in states.values()),
            'Incomplete local checks cannot authorize tagging')


def validate_model(model, context=None):
    require(isinstance(model, dict), 'Invalid fusion model')
    protocol = protocol_for_hash(model.get('protocol_sha256'))
    fields = {'schema', 'version', 'purpose', 'protocol_sha256', 'artifacts', 'weights', 'bias',
              'calibration', 'cutoff', 'supported_profiles', 'manifest_sha256'}
    if protocol.version == 2:
        fields.add('local_binding')
    require(set(model) == fields and model['schema'] == protocol.model_schema
            and model['purpose'] == 'research' and token(model['version'])
            and is_hex(model['manifest_sha256']), 'Invalid fusion model contract')
    if protocol.version == 2:
        validate_local_binding(model['local_binding'])
    if context is not None:
        require(protocol == context.protocol and model.get('local_binding') == context.local_binding,
                'Frozen local detector binding changed')
    cal = model['calibration']
    require(isinstance(model['weights'], list) and len(model['weights']) == len(protocol.features)
            and isinstance(cal, dict) and set(cal) == {'slope', 'intercept', 'messages', 'positive_fraction'},
            'Invalid fusion model dimensions/calibration')
    require(all(numeric(v) and abs(v) <= 1e6 for v in
                [model['bias'], model['cutoff'], cal['slope'], cal['intercept'], *model['weights']])
            and cal['slope'] >= 0 and type(cal['messages']) is int and 2 <= cal['messages'] <= 100_000
            and numeric(cal['positive_fraction']) and 0 < cal['positive_fraction'] < 1,
            'Invalid fusion coefficients/calibration')
    profiles = model['supported_profiles']
    require(isinstance(profiles, list) and 0 < len(profiles) <= 128
            and all(isinstance(p, str) and 0 < len(p) <= 256
                    and all(c in 'abcdefghijklmnopqrstuvwxyz/_' for c in p) for p in profiles)
            and profiles == sorted(set(profiles)), 'Invalid fusion availability profiles')
    if protocol.version == 2:
        require(all(len(p.split('/')) == 14 and all(s in LOCAL_STATES for s in p.split('/')[-2:])
                    for p in profiles), 'Invalid v2 local availability profiles')
    return protocol


def pinned_path(root, entry):
    require(isinstance(entry, dict) and set(entry) == {'path', 'sha256'}
            and isinstance(entry['path'], str) and is_hex(entry['sha256']), 'Invalid pinned input')
    path = (root / entry['path']).resolve()
    digest, consumed = hashlib.sha256(), 0
    with path.open('rb') as source:
        while block := source.read(1024 * 1024):
            consumed += len(block)
            require(consumed <= MAX_BYTES, 'Oversized input')
            digest.update(block)
    require(digest.hexdigest() == entry['sha256'], 'Pinned input hash mismatch')
    return path


def lines(path, maximum=MAX_ROWS + 2, max_line=1024 * 1024):
    consumed = 0
    with path.open('rb') as source:
        for index in range(maximum + 1):
            raw = source.readline(max_line + 1)
            if not raw:
                return
            consumed += len(raw)
            require(index < maximum and len(raw) <= max_line and consumed <= MAX_BYTES,
                    'Oversized JSONL input')
            yield decode(raw)


def components(rows):
    """Transitive exact, declared campaign and SimHash distance <=3 grouping."""
    parents = list(range(len(rows)))

    def find(i):
        while i != parents[i]:
            parents[i] = parents[parents[i]]
            i = parents[i]
        return i

    def union(i, j):
        i, j = find(i), find(j)
        parents[max(i, j)] = min(i, j)

    exact, hashes, buckets = {}, {}, defaultdict(list)
    comparisons = 0
    for i, row in enumerate(rows):
        require(is_hex(row.get('fingerprint')) and is_hex(row.get('simhash'), 16)
                and is_hex(row.get('campaign')), 'Missing campaign provenance')
        for field in ('fingerprint', 'campaign'):
            key = (field, row[field])
            if key in exact:
                union(i, exact[key])
            exact[key] = i
        value = int(row['simhash'], 16)
        if value in hashes:
            union(i, hashes[value])
            continue
        neighbors = set()
        for band in range(4):
            neighbors.update(buckets[(band, (value >> (16 * band)) & 65535)])
        for previous in neighbors:
            comparisons += 1
            require(comparisons <= 5_000_000, 'Campaign comparison budget exceeded')
            if bin(value ^ previous).count('1') <= 3:
                union(i, hashes[previous])
        hashes[value] = i
        for band in range(4):
            buckets[(band, (value >> (16 * band)) & 65535)].append(value)
    groups = defaultdict(list)
    for i in range(len(rows)):
        groups[find(i)].append(i)
    return list(groups.values())


def audit_groups(rows, history):
    all_rows = rows + history
    selected, duplicates, uncertain = [], 0, 0
    for group in components(all_rows):
        current = [i for i in group if i < len(rows)]
        if not current:
            continue
        require(len(current) == len(group), 'Fusion campaign overlaps base-model fitting or prior evaluation')
        require(len({rows[i]['split'] for i in current}) == 1, 'Campaign crosses frozen fusion splits')
        known = [i for i in current if rows[i]['label'] != 'uncertain']
        uncertain += len(current) - len(known)
        if not known:
            continue
        require(len({rows[i]['spam'] for i in known}) == 1, 'Conflicting labels within a campaign')
        selected.append(min(known, key=lambda i: rows[i]['id']))
        duplicates += len(known) - 1
    selected.sort(key=lambda i: rows[i]['id'])
    return [rows[i] for i in selected], {'input': len(rows), 'retained': len(selected),
                                        'uncertain': uncertain, 'duplicates_removed': duplicates}


def load_experiment(manifest_path):
    # Preserve the public five-element v1 return contract.
    return load_experiment_context(manifest_path)[:5]


def load_experiment_context(manifest_path):
    raw = bound_bytes(manifest_path, 64 * 1024)
    manifest = decode(raw)
    require(set(manifest) == {'schema', 'version', 'purpose', 'protocol_sha256', 'vectors',
                             'annotations', 'base_history', 'sampling'}, 'Unsupported manifest fields')
    require(manifest['schema'] == 'noisefence-fusion-experiment-1' and manifest['purpose'] == 'research'
            and token(manifest['version']), 'Invalid experiment contract')
    protocol = protocol_for_hash(manifest['protocol_sha256'])
    sampling = manifest['sampling']
    require(isinstance(sampling, dict) and set(sampling) == {'kind', 'description', 'authorization', 'start_at', 'end_at'}
            and sampling['kind'] in ('corrections', 'synthetic', 'representative')
            and all(isinstance(sampling[k], str) and 0 < len(sampling[k]) <= 2000 for k in ('description', 'authorization'))
            and type(sampling['start_at']) is int and type(sampling['end_at']) is int
            and 0 < sampling['start_at'] <= sampling['end_at'], 'Missing sampling and authorized-use provenance')
    root = manifest_path.parent
    paths = {key: pinned_path(root, manifest[key]) for key in ('vectors', 'annotations', 'base_history')}
    data = list(lines(paths['vectors']))
    require(len(data) >= 3, 'Empty vector export')
    header, footer = data[0], data[-1]
    context = vector_context(header, protocol)
    artifacts = header['artifacts']
    optional_hashes = ('lexical_model_sha256', 'semantic_model_sha256', 'llm_prompt_sha256',
                       'antivirus_database_sha256', 'signatures_database_sha256')
    require(isinstance(artifacts, dict) and set(artifacts) == {'application', 'dependency_lock_sha256', 'policy_sha256',
            'semantic_protocol', 'llm_model_revision', *optional_hashes}
            and token(artifacts['application']) and is_hex(artifacts['dependency_lock_sha256'])
            and is_hex(artifacts['policy_sha256'])
            and all(artifacts[k] is None or is_hex(artifacts[k]) for k in optional_hashes), 'Invalid detector artifacts')
    semantic = json.loads(Path(__file__).with_name('semantic-protocol.json').read_text())
    require(artifacts['semantic_protocol'] == (semantic if artifacts['semantic_model_sha256'] is not None else None),
            'Invalid semantic protocol binding')
    revision = artifacts['llm_model_revision']
    require(revision is None or isinstance(revision, str) and 0 < len(revision) <= 128
            and all(33 <= ord(c) <= 126 for c in revision), 'Invalid cloud model revision')
    require(set(footer) == {'type', 'counts'} and footer['type'] == 'footer', 'Missing complete export footer')
    counts = footer['counts']
    require(set(counts) == {'considered', 'exported', 'missing_evidence', 'non_smtp_evidence', 'ineligible_to_tag'}
            and all(type(v) is int and 0 <= v <= MAX_ROWS for v in counts.values())
            and counts['exported'] == len(data) - 2
            and counts['considered'] == counts['exported'] + counts['missing_evidence'] + counts['non_smtp_evidence'],
            'Inconsistent export coverage')
    annotations = {}
    for annotation in lines(paths['annotations'], MAX_ROWS):
        require(set(annotation) == {'id', 'label', 'split', 'campaign', 'language', 'kind'}
                and is_hex(annotation['id']) and annotation['id'] not in annotations
                and annotation['label'] in ('legit', 'spam', 'phishing', 'uncertain', 'unwanted_binary')
                and annotation['split'] in SPLITS and is_hex(annotation['campaign'])
                and token(annotation['language']) and token(annotation['kind']), 'Invalid human annotation')
        annotations[annotation['id']] = annotation
    minimum = np.array([f.minimum for f in protocol.features])
    maximum = np.array([f.maximum for f in protocol.features])
    rows, ids = [], set()
    for row in data[1:-1]:
        require(set(row) == {'type', 'id', 'fingerprint', 'simhash', 'observed_at', 'labelled_at', 'source',
                             'spam', 'availability_profile', 'tag_eligible', 'legacy_score', 'values'}
                and row['type'] == 'row' and is_hex(row['id']) and row['id'] not in ids
                and row['source'] == 'local_human_feedback' and type(row['spam']) is bool
                and type(row['tag_eligible']) is bool and type(row['observed_at']) is int
                and type(row['labelled_at']) is int and row['labelled_at'] >= row['observed_at']
                and sampling['start_at'] <= row['observed_at'] <= sampling['end_at']
                and isinstance(row['availability_profile'], str) and 0 < len(row['availability_profile']) <= 256
                and all(c in 'abcdefghijklmnopqrstuvwxyz/_' for c in row['availability_profile'])
                and (row['legacy_score'] is None or numeric(row['legacy_score']) and 0 <= row['legacy_score'] <= 100),
                'Invalid exported row')
        require(isinstance(row['values'], list) and len(row['values']) == len(minimum)
                and all(numeric(v) for v in row['values']), 'Invalid native feature vector')
        vector = np.array(row['values'])
        require(np.all(vector >= minimum) and np.all(vector <= maximum), 'Feature outside native bounds')
        validate_local_vector(row, context)
        annotation = annotations.get(row['id'])
        require(annotation is not None and (annotation['label'] == 'uncertain'
                or row['spam'] == (annotation['label'] != 'legit')), 'Annotation conflicts with human feedback')
        rows.append({**row, **annotation})
        ids.add(row['id'])
    require(ids == set(annotations) and counts['ineligible_to_tag'] == sum(not r['tag_eligible'] for r in rows),
            'Annotation or availability coverage mismatch')
    history = decode(bound_bytes(paths['base_history'], 32 * 1024 * 1024))
    require(set(history) == {'schema', 'lexical_model_sha256', 'semantic_model_sha256', 'complete_for', 'rows'}
            and history['schema'] == 'noisefence-base-history-1' and history['complete_for'] == BASE_USES
            and all(history[key] == artifacts[key] for key in ('lexical_model_sha256', 'semantic_model_sha256'))
            and isinstance(history['rows'], list) and len(history['rows']) <= 100_000,
            'Missing complete supervised base-model campaign history')
    require(bool(history['rows']) or all(history[k] is None for k in ('lexical_model_sha256', 'semantic_model_sha256')),
            'Loaded base models need an explicit complete campaign history')
    require(all(set(r) == {'fingerprint', 'simhash', 'campaign'} for r in history['rows']), 'Unexpected base-history fields')
    rows, grouping = audit_groups(rows, history['rows'])
    for split in SPLITS:
        labels = {row['spam'] for row in rows if row['split'] == split}
        require(labels == {False, True}, f'{split} needs both classes after grouping')
    # Recheck bytes after parsing: a concurrently replaced input cannot be bound to
    # a manifest hash for different contents.
    for key, path in paths.items():
        require(pinned_path(root, manifest[key]) == path, 'Input changed during loading')
    return manifest, hashlib.sha256(raw).hexdigest(), artifacts, rows, {'export': counts, 'grouping': grouping}, context


def wilson(success, total):
    if not total:
        return None
    z = 1.959963984540054
    p, d = success / total, 1 + z*z/total
    midpoint = (p + z*z/(2*total)) / d
    radius = z * math.sqrt(p*(1-p)/total + z*z/(4*total*total)) / d
    return [max(0., midpoint-radius), min(1., midpoint+radius)]


def metrics(labels, predicted):
    labels, predicted = np.asarray(labels, dtype=bool), np.asarray(predicted, dtype=bool)
    tp, fp = int(np.sum(labels & predicted)), int(np.sum(~labels & predicted))
    positive, negative = int(labels.sum()), int((~labels).sum())
    return {'tp': tp, 'fp': fp, 'fn': positive-tp, 'tn': negative-fp,
            'recall': tp/positive if positive else None, 'fpr': fp/negative if negative else None,
            'precision': tp/(tp+fp) if tp+fp else None,
            'recall_ci95': wilson(tp, positive), 'fpr_ci95': wilson(fp, negative),
            'precision_ci95': wilson(tp, tp+fp)}


def choose_cutoff(labels, logits, eligible):
    """One empirical FPR-constrained cutoff, ties indivisible, numerical gap kept."""
    labels, logits, eligible = np.asarray(labels, bool), np.asarray(logits, float), np.asarray(eligible, bool)
    require(np.isfinite(logits).all() and np.any(~labels) and np.any(labels), 'Invalid threshold lot')
    indices = np.flatnonzero(eligible)
    indices = indices[np.argsort(-logits[indices], kind='stable')]
    gap = 1e-9 * max(1., float(np.max(np.abs(logits))))
    best, best_key = float(np.max(logits) + gap), (0, 0)
    tp = fp = 0
    max_fp = math.floor(int((~labels).sum()) * TARGET_FPR)
    for position, index in enumerate(indices):
        tp += int(labels[index])
        fp += int(not labels[index])
        if fp > max_fp:
            break
        next_value = logits[indices[position+1]] if position+1 < len(indices) else logits[index]-4*gap
        if logits[index] - next_value <= 2*gap:
            continue
        key = (tp, -fp)
        if key > best_key:
            best, best_key = float(next_value/2 + logits[index]/2), key
    return best


def calibrate(logits, labels):
    logits, labels = np.asarray(logits, float), np.asarray(labels, float)
    require(0 < labels.mean() < 1, 'Calibration requires both classes')

    def objective(parameters):
        slope, intercept = parameters
        z = slope*logits + intercept
        error = expit(z)-labels
        penalty = 1e-6
        loss = np.mean(np.logaddexp(0, z)-labels*z) + penalty*np.sum(parameters**2)/2
        gradient = np.array([np.mean(error*logits), np.mean(error)]) + penalty*parameters
        return loss, gradient

    result = minimize(objective, [1., 0.], jac=True, method='L-BFGS-B',
                      bounds=((0., 100.), (-100., 100.)), options={'maxiter': 2000, 'ftol': 1e-12, 'gtol': 1e-8})
    require(result.success and np.isfinite(result.x).all(), 'Calibration did not converge')
    return {'slope': float(result.x[0]), 'intercept': float(result.x[1]),
            'messages': len(labels), 'positive_fraction': float(labels.mean())}


def calibration_metrics(labels, probabilities):
    labels, probabilities = np.asarray(labels, float), np.asarray(probabilities, float)
    p = np.clip(probabilities, 1e-15, 1-1e-15)
    bins = []
    for index in range(10):
        mask = (probabilities >= index/10) & (probabilities < (index+1)/10 if index < 9 else probabilities <= 1)
        if mask.any():
            bins.append({'lower': index/10, 'upper': (index+1)/10, 'count': int(mask.sum()),
                         'mean_probability': float(probabilities[mask].mean()),
                         'positive_fraction': float(labels[mask].mean())})
    return {'brier': float(np.mean((probabilities-labels)**2)),
            'log_loss': float(-np.mean(labels*np.log(p)+(1-labels)*np.log1p(-p))), 'bins': bins}


def model_predictions(model, rows, context=None):
    protocol = validate_model(model, context)
    require(all(isinstance(r['values'], list) and len(r['values']) == len(protocol.features)
                and all(numeric(value) and feature.minimum <= value <= feature.maximum
                        for value, feature in zip(r['values'], protocol.features)) for r in rows),
            'Invalid native feature vector for model protocol')
    if protocol.version == 2:
        local_context = context or ExperimentContext(protocol, model['local_binding'])
        for row in rows:
            validate_local_vector(row, local_context)
    matrix = np.array([r['values'] for r in rows], dtype=float)
    logits = matrix @ np.array(model['weights']) + model['bias']
    cal = model['calibration']
    probabilities = expit(cal['slope'] * logits + cal['intercept'])
    eligible = np.array([r['tag_eligible'] and r['availability_profile'] in model['supported_profiles'] for r in rows])
    return logits, probabilities, eligible & (logits >= model['cutoff'])


def private_json(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as output:
        json.dump(value, output, ensure_ascii=False, indent=2, allow_nan=False)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())


def fit(manifest_path, output):
    manifest, manifest_hash, artifacts, rows, audit, context = load_experiment_context(manifest_path)
    protocol = context.protocol
    require(not output.exists(), 'Output already exists; keep frozen experiments immutable')
    output.mkdir(parents=True, mode=0o700)
    parts = {split: [r for r in rows if r['split'] == split] for split in SPLITS}
    matrices = {s: np.array([r['values'] for r in parts[s]], float) for s in SPLITS[:-1]}
    labels = {s: np.array([r['spam'] for r in parts[s]], bool) for s in SPLITS[:-1]}
    training_profiles = set(r['availability_profile'] for r in parts['train'])
    profiles = sorted(training_profiles & set(r['availability_profile'] for r in parts['calibration']))
    require(0 < len(profiles) <= 128, 'No shared training/calibration availability profiles')
    eligible = {s: np.array([r['tag_eligible'] and r['availability_profile'] in profiles for r in parts[s]])
                for s in SPLITS[:-1]}
    # Calibration coverage must not affect hyperparameter selection on development.
    eligible['development'] = np.array([r['tag_eligible'] and r['availability_profile'] in training_profiles
                                        for r in parts['development']])
    choices, hashes = {}, {}
    for variant, families in protocol.variants:
        mask = np.array([f.family in families for f in protocol.features])
        scaler = StandardScaler().fit(matrices['train'][:, mask])
        train = scaler.transform(matrices['train'][:, mask])
        candidates = []
        for c in GRID:
            with warnings.catch_warnings():
                warnings.simplefilter('error', ConvergenceWarning)
                estimator = LogisticRegression(C=c, solver='lbfgs', max_iter=2000, tol=1e-8)
                estimator.fit(train, labels['train'])
            weights = np.zeros(len(mask))
            weights[mask] = estimator.coef_[0]/scaler.scale_
            bias = float(estimator.intercept_[0] - np.dot(weights[mask], scaler.mean_))
            dev = matrices['development'] @ weights + bias
            cutoff = choose_cutoff(labels['development'], dev, eligible['development'])
            result = metrics(labels['development'], eligible['development'] & (dev >= cutoff))
            candidates.append((result, c, weights, bias))
        selected = max(candidates, key=lambda v: (v[0]['recall'], -v[0]['fpr'], -v[1]))
        _, c, weights, bias = selected
        logits = {s: matrices[s] @ weights + bias for s in SPLITS[:-1]}
        model = {'schema': protocol.model_schema, 'version': manifest['version']+'-'+variant,
                 'purpose': 'research', 'protocol_sha256': protocol.sha256, 'artifacts': artifacts,
                 'weights': weights.tolist(), 'bias': bias,
                 'calibration': calibrate(logits['calibration'], labels['calibration']),
                 'cutoff': choose_cutoff(labels['threshold'], logits['threshold'], eligible['threshold']),
                 'supported_profiles': profiles, 'manifest_sha256': manifest_hash}
        if protocol.version == 2:
            model['local_binding'] = context.local_binding
        require(token(model['version']) and all(math.isfinite(v) and abs(v) <= 1e6 for v in [bias, model['cutoff'], *weights]),
                'Model exceeds native contract bounds')
        validate_model(model, context)
        private_json(output / (variant+'.json'), model)
        hashes[variant] = hashlib.sha256((output / (variant+'.json')).read_bytes()).hexdigest()
        choices[variant] = {'selected_C': c, 'development_grid': [{'C': v[1], 'metrics': v[0]} for v in candidates],
                            'threshold': metrics(labels['threshold'], eligible['threshold'] & (logits['threshold'] >= model['cutoff']))}
    # This receipt is written only after every frozen model succeeds. Evaluation
    # verifies it and reuses those coefficients; it never refits a variant.
    receipt = {'schema': 'noisefence-fusion-fit-1', 'manifest_sha256': manifest_hash, 'models_sha256': hashes,
               'protocol_sha256': protocol.sha256, 'choices': choices, 'audit': audit,
               'fit_counts': {s: dict(Counter('unwanted' if r['spam'] else 'legit' for r in parts[s])) for s in SPLITS[:-1]},
               'availability_counts': {s: dict(Counter(r['availability_profile'] for r in parts[s])) for s in SPLITS[:-1]},
               'test_evaluated': False, 'production_eligible': False}
    private_json(output / 'fit.json', receipt)
    return receipt


def evaluate(manifest_path, output):
    manifest, manifest_hash, artifacts, rows, audit, context = load_experiment_context(manifest_path)
    protocol = context.protocol
    require(not (output / 'test.json').exists(), 'Test already consumed for this frozen experiment')
    receipt = decode(bound_bytes(output / 'fit.json', 2 * 1024 * 1024))
    require(receipt['schema'] == 'noisefence-fusion-fit-1' and receipt['manifest_sha256'] == manifest_hash
            and receipt['protocol_sha256'] == protocol.sha256
            and set(receipt['models_sha256']) == set(protocol.variant_names), 'Frozen experiment mismatch')
    test = [r for r in rows if r['split'] == 'test']
    labels = np.array([r['spam'] for r in test], bool)
    results = {}
    for variant in protocol.variant_names:
        raw = bound_bytes(output / (variant+'.json'), 128 * 1024)
        require(hashlib.sha256(raw).hexdigest() == receipt['models_sha256'][variant], 'Frozen model changed')
        model = decode(raw)
        require(model['manifest_sha256'] == manifest_hash and model['artifacts'] == artifacts, 'Frozen detector cohort changed')
        _, probabilities, predictions = model_predictions(model, test, context)
        strata = {}
        for field in ('language', 'kind', 'label', 'availability_profile'):
            strata[field] = {value: metrics(labels[mask], predictions[mask]) for value in sorted({r[field] for r in test})
                            for mask in [np.array([r[field] == value for r in test])]}
        results[variant] = {'metrics': metrics(labels, predictions), 'calibration': calibration_metrics(labels, probabilities),
                            'by_stratum': strata, 'unsupported_profiles': sum(r['availability_profile'] not in model['supported_profiles'] for r in test)}
    # Legacy score is a baseline only. Tune its single threshold on the same
    # reserved threshold lot; do not give the baseline access to test labels.
    threshold = [r for r in rows if r['split'] == 'threshold']
    baseline = None
    if all(r['legacy_score'] is not None for r in threshold + test):
        point = choose_cutoff([r['spam'] for r in threshold], [r['legacy_score'] for r in threshold], [r['tag_eligible'] for r in threshold])
        baseline = {'threshold': point, 'metrics': metrics(labels, [r['tag_eligible'] and r['legacy_score'] >= point for r in test])}
    m = results['full']['metrics']
    enough = int((~labels).sum()) >= 10_000 and int(labels.sum()) >= 2_000
    report = {'schema': 'noisefence-fusion-test-1', 'manifest_sha256': manifest_hash, 'audit': audit,
              'sampling_kind': manifest['sampling']['kind'], 'variants': results, 'legacy_baseline': baseline,
              'target_observed': m['recall'] >= .95 and m['fpr'] <= TARGET_FPR,
              'target_supported_on_this_test': enough and manifest['sampling']['kind'] == 'representative'
                  and m['recall'] >= .95 and m['fpr_ci95'][1] <= TARGET_FPR,
              'test_evaluated': True, 'production_eligible': False,
              'limitations': ['Campaign grouping is a heuristic; metrics use one representative per campaign.',
                              'Ablations remove feature families on fixed observations, not connector executions or LLM selection.',
                              'Representativeness and complete base history require an external provenance audit.',
                              'Calibration is specific to the observed mixture and detector availability.',
                              'Foundational pretraining and exact cloud/ClamD revisions may be unknown.',
                              'This report does not establish Proton delivery compatibility or latency.']}
    private_json(output / 'test.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('fit', 'evaluate'))
    parser.add_argument('manifest', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    result = (fit if args.action == 'fit' else evaluate)(args.manifest, args.output)
    print(json.dumps({'schema': result['schema'], 'production_eligible': False,
                      'test_evaluated': result['test_evaluated']}))


if __name__ == '__main__':
    main()
