#!/usr/bin/env python3
"""Compare recorded engines against human labels, without retraining or network I/O."""
from collections import Counter
import math
from train_quality import load_dataset, read_jsonl, components, readiness, partition
from quality_metrics import outcomes, metrics
from evaluate_quality import baseline


def rspamd_outcome(row):
    report=row.get('rspamd') or {}
    if report.get('status')!='complete':return 'review'
    return {'no action':'legitimate','accept':'legitimate','reject':'spam',
            'add header':'spam','rewrite subject':'spam'}.get(report.get('action'),'review')


def compare(dataset):
    header,usable,coverage,_,digest=load_dataset(dataset,allow_multiple_artifacts=True)
    records,again=read_jsonl(dataset)
    if digest!=again:raise ValueError('Dataset changed during comparison')
    rows=records[1:-1]
    labelled=[r for r in rows if r.get('risk') in ('legitimate','spam')]
    y=[int(r['risk']=='spam') for r in labelled]
    native=[baseline(r) for r in labelled];other=[rspamd_outcome(r) for r in labelled]
    scored=[r for r in labelled if type(r.get('legacy_score')) in (int,float) and math.isfinite(r['legacy_score']) and 0<=r['legacy_score']<=100]
    lexical=metrics([int(r['risk']=='spam') for r in scored],[r['legacy_score']/100 for r in scored],.05,.95)
    # This is reliability of the *historical index*, never proof it is a probability.
    lexical['interpretation']='historical_index_not_calibrated_probability'
    cohorts=Counter(r['quality']['artifacts_sha256'] for r in usable)
    splits={}
    for cohort in sorted(cohorts):
        group=[r for r in usable if r['quality']['artifacts_sha256']==cohort]
        parts,grouping=partition(group,'risk',header['partition_cuts'])
        splits[cohort]={'messages':len(group),'readiness':readiness(parts,'risk'),'grouping':grouping}
    identified=[dict(r,campaign=r['fingerprint']) for r in labelled if r.get('fingerprint') and r.get('simhash')]
    representatives=[];conflicts=0
    for indexes in components(identified):
        group=[identified[i] for i in indexes]
        if len({r['risk'] for r in group})>1:conflicts+=1;continue
        representatives.append(min(group,key=lambda r:r['id']))
    cy=[int(r['risk']=='spam') for r in representatives]
    latency=sorted(r['pipeline_elapsed_ms'] for r in rows if type(r.get('pipeline_elapsed_ms')) in (int,float) and 0<=r['pipeline_elapsed_ms']<=3600000)
    report={'schema':'noisefence-quality-comparison-1','dataset_sha256':digest,'purpose':header.get('purpose','regression'),'sampling':header['sampling'],
      'coverage':{**coverage,'labelled':len(labelled),'unlabelled_or_uncertain':len(rows)-len(labelled)},
      'baseline':outcomes(y,native),'rspamd':outcomes(y,other),'legacy_score_calibration':lexical,
      'campaigns':{'count':len(representatives),'conflicting':conflicts,
        'baseline':outcomes(cy,[baseline(r) for r in representatives]),
        'rspamd':outcomes(cy,[rspamd_outcome(r) for r in representatives])},
      'cohorts':splits,'rspamd_profiles':dict(Counter((r.get('rspamd') or {}).get('settings_sha256','missing') for r in rows)),
      'pipeline_latency':{'samples':len(latency),'p95_ms':latency[max(0,math.ceil(.95*len(latency))-1)] if latency else None,
        'scope':'recorded_end_to_end_including_external_services','native_p95_ms':None},
      'slices':{},'observation_only':True,'may_activate':False,
      'limitations':['Human labels are the reference; Rspamd actions are predictions.',
        'Message intervals assume independent observations; also inspect campaign metrics.',
        'A previously examined sample is a regression set, not independent qualification.',
        'Recorded total latency cannot establish native warm-cache performance.']}
    for kind in ('conversation','transactional','notification','newsletter','promotion','other',None):
        group=[r for r in labelled if r.get('kind')==kind];labels=[int(r['risk']=='spam') for r in group]
        report['slices'][kind or 'unlabelled_type']={'baseline':outcomes(labels,[baseline(r) for r in group]),'rspamd':outcomes(labels,[rspamd_outcome(r) for r in group])}
    return report
