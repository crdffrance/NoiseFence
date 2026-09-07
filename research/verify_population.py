#!/usr/bin/env python3
"""Full-population synthetic software check using already frozen parity models."""
from collections import Counter
import copy
import hashlib
import json
import os

import evaluate_population as population
import train_fusion as f


def pin(path):
    return {'path': str(path.resolve()), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def verify(experiment, binary, output):
    output.mkdir(parents=True, mode=0o700)
    originals = list(f.lines(experiment/'observations.jsonl'))
    rows, annotations = [], []
    for i, original in enumerate(originals):
        key = hashlib.sha256(('population software fixture '+str(i)).encode()).hexdigest()
        evidence = copy.deepcopy(original['evidence'])
        label = {'status':'consensus', 'unwanted':original['spam'], 'labelled_at':1788739900,
                 'authorized_votes':1, 'ignored_votes':0}
        row = {'type':'row', 'id':key, 'observed_at':1788739200+i, 'raw_sha256':key,
               'fingerprint':key, 'simhash':key[:16], 'complete':evidence['analysis_complete'],
               'features_complete':True, 'decision':None, 'tagged':False, 'label':label,
               'evidence_status':'smtp', 'evidence':evidence}
        annotation = {'id':key, 'label':'unwanted_binary' if original['spam'] else 'legit',
                      'campaign':key, 'language':'fr', 'kind':'software-fixture', 'basis':'feedback',
                      'review_reference':'Fabricated software-test annotation; no human traffic', 'reviewed_at':1788740000}
        if i == 1:
            row['complete'] = False  # An old decision must not replace detector completeness.
        if i in (2,3,4):
            row.update(evidence=None, evidence_status={2:'missing',3:'non_smtp',4:'invalid'}[i])
        if i == 5:
            evidence['artifacts']['policy_sha256'] = 'f'*64
        if i == 6:
            evidence['analysis_complete'] = False
            row['complete'] = False
        if i == 7:
            row.update(raw_sha256=None, fingerprint=None, simhash=None)
            annotation['campaign'] = None
        if i == 8:
            annotation.update(label='uncertain', basis='unresolved', review_reference=None, reviewed_at=None)
        if i == 9:
            label.update(status='conflicting', unwanted=None, authorized_votes=2)
            annotation['basis'] = 'adjudicated'
        if i == 10:
            label.update(status='unlabelled', unwanted=None, labelled_at=None, authorized_votes=0)
            annotation['basis'] = 'reviewed'
        if i == 20:
            row.update(fingerprint=rows[0]['fingerprint'], simhash=rows[0]['simhash'])
            annotation['campaign'] = annotations[0]['campaign']
        rows.append(row)
        annotations.append(annotation)
    count = Counter(r['evidence_status'] for r in rows)
    labels = Counter(r['label']['status'] for r in rows)
    counts = {'considered':len(rows)+1, 'automatic_dsn':1, 'exported':len(rows),
              'labelled':labels['consensus'], 'unlabelled':labels['unlabelled'],
              'conflicting_labels':labels['conflicting'], 'invalid_labels':0, 'ignored_feedback':0,
              'incomplete':sum(not r['complete'] for r in rows), 'invalid_scan':0,
              'missing_raw_hash':1, 'missing_campaign':1, 'missing_evidence':count['missing'],
              'non_smtp_evidence':count['non_smtp'], 'invalid_evidence':count['invalid'], 'smtp_evidence':count['smtp']}
    data = [{'type':'header','schema':'noisefence-population-1','since':1788739200,'until':1788739600,
             'captured_at':1788740000,'scope':'retained_accepted_messages','sampling':'unreviewed','contains_bodies':False}]
    data += rows + [{'type':'footer','schema':'noisefence-population-1','report':counts}]
    for name, records in (('population.jsonl',data), ('annotations.jsonl',annotations)):
        path = output/name
        # All fixtures, still private because the production contract is private.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as target:
            for record in records:
                target.write(json.dumps(record, allow_nan=False)+'\n')
    candidate = experiment/'candidate'
    manifest = {'schema':population.SCHEMA, 'population':pin(output/'population.jsonl'),
                'annotations':pin(output/'annotations.jsonl'), 'experiment':pin(experiment/'manifest.json'),
                'fit':pin(candidate/'fit.json'), 'models':{v:pin(candidate/(v+'.json')) for v in f.VARIANTS},
                'binary':pin(binary), 'sampling':{'kind':'synthetic', 'description':'Complete synthetic snapshot',
                'authorization':'Software fixtures only', 'start_at':1788739200,'end_at':1788739600},
                'review':{'reference':'Synthetic software test; no quality claim', 'reviewed_at':1788740000,
                          'blinded':False, 'independent_campaigns':False}}
    path = output/'manifest.json'
    f.private_json(path, manifest)
    report = population.evaluate(path, output/'evaluation')
    checked = 0
    for variant in f.VARIANTS:
        result = report['variants'][variant]
        m = result['metrics']
        f.require(m['population'] == 400 and m['unassessable'] == 4 and m['unknown_truth'] == 1,
                  'Population omissions escaped the denominators')
        f.require(not result['target_supported_on_this_population'], 'Synthetic data authorized a quality claim')
        previous = {r['id']:r['prediction'] for r in f.lines(experiment/(variant+'-native.jsonl')) if r['type'] == 'row'}
        current = [r for r in f.lines(output/'evaluation'/(variant+'.predictions.jsonl')) if r['type'] == 'row']
        for i, row in enumerate(current):
            if i in (2,3,4,5):
                f.require(row['prediction'] is None, 'Missing evidence became a negative prediction')
            elif i == 6:
                f.require(row['prediction']['would_tag'] is False, 'Incomplete analysis escaped fail-open')
            else:
                f.require(row['prediction'] == previous[originals[i]['id']], 'Population and ordinary native prediction differ')
            checked += 1
    try:
        population.evaluate(path, output/'repeated-evaluation')
    except FileExistsError:
        pass
    else:
        raise AssertionError('Population test could be silently reused')
    result = {'schema':'noisefence-population-software-validation-1', 'synthetic':True,
              'population_rows':len(rows), 'predictions_checked':checked,
              'unassessable_per_variant':4, 'unknown_truth_per_variant':1,
              'decision_disagreements':0, 'reuse_refused':True, 'production_eligible':False,
              'mail_sent':False, 'external_analysis_calls':0}
    f.private_json(output/'software-validation.json', result)
    return result
