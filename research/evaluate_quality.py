#!/usr/bin/env python3
"""Evaluate a frozen shadow candidate on a separate, human-labelled uniform sample.

Read-only on inputs; aggregate output only. Never tunes thresholds, calls a
provider, changes a message or grants activation. Missing decisions are review.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import time

from train_quality import load_dataset, read_jsonl, components, KINDS, PROTOCOL_HASH
from train_fusion import require, is_hex, decode
from quality_runtime import load_model, predict
from quality_metrics import outcomes, acceptance, metrics, interval


def baseline(row):
    decision=row.get('legacy_decision') or {}
    value=decision.get('outcome')
    if decision.get('source')!='antivirus':
        value={'publicity':'legitimate','spam':'unwanted','legitimate':'legitimate','undetermined':'undetermined'}.get(row.get('delivery_classification'),value)
        if row.get('baseline_complete') is False:
            value='undetermined'
    return {'unwanted':'spam','legitimate':'legitimate'}.get(value,'review')


def evaluate(dataset, model_path, manifest_path):
    model,model_bytes=load_model(model_path)
    require(model['trained_at']<=time.time()+60,'Future candidate timestamp')
    with manifest_path.open('rb') as f:
        raw=f.read(32*1024*1024+1)
    require(len(raw)<=32*1024*1024 and hashlib.sha256(raw).hexdigest()==model['training_manifest_sha256'],'Training manifest does not match candidate')
    manifest=decode(raw)
    require(isinstance(manifest,dict) and manifest.get('schema')=='noisefence-quality-training-manifest-1' and manifest.get('dataset_sha256')==model['dataset_sha256']
            and manifest.get('protocol_sha256')==PROTOCOL_HASH and manifest.get('artifacts_sha256')==model['artifacts_sha256'],'Invalid training provenance')
    history=manifest.get('campaigns')
    require(isinstance(history,list) and 0<len(history)<=100000 and all(isinstance(r,dict) and all(is_hex(r.get(k),16 if k=='simhash' else 64) for k in ('fingerprint','simhash','campaign')) for r in history),'Invalid training campaigns')
    require(type(manifest.get('until')) is int and type(manifest.get('captured_at')) is int and manifest['until']<=manifest['captured_at']<=model['trained_at'],'Invalid training interval')
    header,usable,_,_,digest=load_dataset(dataset,allow_multiple_artifacts=True)
    data,second_digest=read_jsonl(dataset)
    require(second_digest==digest,'Dataset changed during evaluation')
    rows=data[1:-1]
    identified=[{**r,'campaign':r['fingerprint']} for r in rows if is_hex(r.get('fingerprint')) and is_hex(r.get('simhash'),16)]
    combined=history+identified
    overlap=set();groups=[]
    for group in components(combined):
        current=[combined[i] for i in group if i>=len(history)]
        if not current:continue
        if any(i<len(history) for i in group):overlap.update(r['id'] for r in current)
        groups.append(current)
    supported={r['id']:r for r in usable}
    coverage=Counter(retained=len(rows),selected=header['selected'],deleted_or_no_longer_authorized=header['selected']-len(rows),
                     unverifiable_campaigns=len(rows)-len(identified),overlapping_messages=len(overlap))
    y,before,after,detector,probabilities,available=[],[],[],[],[],[]
    by_id={};kind_confusion=[[0]*7 for _ in range(6)]
    for row in rows:
        if row['risk'] in (None,'uncertain'):
            coverage['unlabelled_or_uncertain']+=1
            continue
        label=int(row['risk']=='spam');old=baseline(row);result=None
        if row['id'] in supported and row['observed_at']<=model['trained_at']+30*86400:
            try:result=predict(model,supported[row['id']]['quality'])
            except ValueError:pass
        if result is None:
            coverage['unsupported_observations']+=1
        candidate=result['risk'] if result else 'review'
        guarded=candidate
        if (row.get('legacy_decision') or {}).get('source')=='antivirus' and old=='spam':
            guarded='spam';coverage['antivirus_priority']+=1
        if (row.get('legacy_decision') or {}).get('outcome') not in ('unwanted','legitimate','undetermined'):
            coverage['missing_baseline']+=1
        y.append(label);before.append(old);after.append(guarded);detector.append(candidate)
        probabilities.append(result['risk_probability'] if result else 0.)
        available.append(result is not None)
        by_id[row['id']]=(label,old,guarded,row.get('kind'))
        if row.get('kind') in KINDS:
            k=result['kind'] if result else 'unavailable'
            kind_confusion[KINDS.index(row['kind'])][KINDS.index(k) if k in KINDS else 6]+=1
    cy,cb,ca=[],[],[]
    for group in groups:
        labelled=[r for r in group if r['id'] in by_id]
        if not labelled:continue
        coverage['duplicate_campaign_messages']+=max(0,len(group)-1)
        if len({r['risk'] for r in labelled})!=1:
            coverage['conflicting_campaigns']+=1;continue
        row=min(labelled,key=lambda r:r['id'])
        a,b,c,_=by_id[row['id']];cy.append(a);cb.append(b);ca.append(c)
    prospective=header['since']>=model['trained_at'] and header['since']>=manifest['until'] and digest!=model['dataset_sha256']
    base_provenance=is_hex(manifest.get('base_history_sha256')) and manifest.get('unverifiable_seen_campaigns')==0
    independent=(base_provenance and prospective and not overlap and not coverage['unverifiable_campaigns'] and not coverage['duplicate_campaign_messages'] and not coverage['conflicting_campaigns'])
    complete=(coverage['retained']==header['selected'] and len(y)==len(rows) and not coverage['unsupported_observations'] and not coverage['missing_baseline'])
    b,a=outcomes(y,before),outcomes(y,after)
    report={'schema':'noisefence-quality-evaluation-1','model_sha256':hashlib.sha256(model_bytes).hexdigest(),'model_version':model['version'],
            'dataset_sha256':digest,'training_manifest_sha256':model['training_manifest_sha256'],
            'sampling':'uniform_message','coverage':dict(coverage),'prospective':prospective,'base_training_provenance_verified':base_provenance,
            'baseline':b,'candidate':a,'detector_without_antivirus_guard':outcomes(y,detector),
            'risk_calibration':metrics(y,probabilities,*model['thresholds'],available),
            'campaigns':{'baseline':outcomes(cy,cb),'candidate':outcomes(cy,ca)},
            'acceptance':acceptance(a,b,independent,complete),
            'mail_kind':{'classes':KINDS,'prediction_classes':KINDS+['unavailable'],'confusion':kind_confusion,
                         'recall_ci95':{kind:interval(kind_confusion[i][i],sum(kind_confusion[i])) for i,kind in enumerate(KINDS)}},
            'slices':{},'observation_only':True,'may_activate':False,
            'limitations':['Recorded controls only: a different provider/LLM selection, recipient rules and Proton placement are not replayed.',
                           'Message confidence intervals assume independent messages; repeated campaigns block the final gate.',
                           'No automatic activation; independent report review and operational validation remain required.']}
    # Consented newsletters and promotions are a mail type, not a spam label.
    kind_y,kind_predictions=[],[]
    publicity={KINDS.index('newsletter'),KINDS.index('promotion')}
    for i,line in enumerate(kind_confusion):
        for j,count in enumerate(line):
            kind_y.extend([int(i in publicity)]*count)
            kind_predictions.extend([('review' if j==6 else 'spam' if j in publicity else 'legitimate')]*count)
    report['mail_kind']['publicity']=outcomes(kind_y,kind_predictions)
    for kind in [*KINDS,None]:
        subset=[v for v in by_id.values() if v[3]==kind]
        report['slices'][kind or 'unlabelled_type']={'baseline':outcomes([v[0] for v in subset],[v[1] for v in subset]),
                                                   'candidate':outcomes([v[0] for v in subset],[v[2] for v in subset])}
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('dataset',type=Path);parser.add_argument('--model',type=Path,required=True)
    parser.add_argument('--training-manifest',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();os.umask(0o077)
    report=evaluate(args.dataset,args.model,args.training_manifest)
    # An existing report/test result is immutable, including symlinks.
    with args.output.open('x') as f:
        json.dump(report,f,indent=2,allow_nan=False);f.write('\n');f.flush();os.fsync(f.fileno())
    print(json.dumps(report,allow_nan=False))
    return 0 if report['acceptance']['passes_pilot'] else 3


if __name__=='__main__':raise SystemExit(main())
