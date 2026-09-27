#!/usr/bin/env python3
"""Offline small-sample diagnostic; never a loadable production model.

Compare monotone, regularized evidence combinations on human corrections.
Mixed historical detector cohorts are reported, not certified as compatible.
No Rspamd predictions, message bodies or automatic labels enter fitting.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import time

import numpy as np
from scipy.optimize import minimize
from scipy.special import expit
from sklearn.metrics import roc_auc_score

from train_fusion import components, lines, require, numeric, is_hex
from quality_metrics import outcomes

FEATURES = ('lexical_logit', 'semantic_logit', 'llm_risk', 'aligned_authentication',
            'spf_failure', 'dmarc_failure', 'malware', 'phishing_signature')
RIDGE = .02


def vector(evidence):
    require(isinstance(evidence, dict) and evidence.get('schema') == 'noisefence-evidence-1'
            and evidence.get('source') == 'smtp_session', 'Observed SMTP evidence required')
    def content(name):
        value=evidence.get(name+'_logit')
        available=evidence.get(name+'_state')=='complete' and numeric(value)
        return float(np.clip(value,-12,12)/12) if available else 0., available
    lexical,lx=content('lexical');semantic,sx=content('semantic')
    llm=evidence.get('llm') or {};a=evidence.get('authentication') or {}
    p,c=llm.get('reported_probability'),llm.get('reported_confidence')
    coherent=(numeric(p) and numeric(c) and 0<=p<=1 and 0<=c<=1 and
              ((llm.get('category')=='legitimate' and p<.5) or
               (llm.get('category') in ('spam','phishing') and p>.5)))
    llm_available=llm.get('state')=='complete' and llm.get('outcome')=='complete' and coherent
    aligned=a.get('dmarc_state')=='complete' and 'pass' in (a.get('dmarc_spf'),a.get('dmarc_dkim'))
    spf=a.get('spf_state')=='complete' and a.get('spf') in ('fail','soft_fail')
    dmarc=(a.get('dmarc_state')=='complete' and
           a.get('dmarc_spf')=='fail' and a.get('dmarc_dkim')=='fail')
    av=evidence.get('antivirus') or {};signatures=evidence.get('signatures') or {}
    malware=evidence.get('antivirus_state')=='complete' and av.get('status')=='malware'
    signature=(evidence.get('signatures_state')=='complete' and signatures.get('status')=='suspicious'
               and str(signatures.get('signature') or '').startswith('Sanesecurity.Phishing.'))
    # Trust is signed negative; all learned weights are non-negative. Missing
    # results contribute neither positive nor negative evidence.
    values=[lexical,semantic,(2*p-1)*c if llm_available else 0.,-float(aligned),
            float(spf),float(dmarc),float(malware),float(signature)]
    profile=f'{int(lx)}/{int(sx)}/{int(llm_available)}/{a.get("state","unavailable")}'
    return values,profile


def load(path, role):
    rows=[];excluded=Counter()
    require(path.stat().st_size<=512*1024*1024,'Oversized diagnostic input')
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        while block:=stream.read(1024*1024):digest.update(block)
    digest=digest.hexdigest()
    for row in lines(path, maximum=5000, max_line=16*1024*1024):
        require(row.get('schema')=='noisefence-learning-1' and
                row.get('source')==('local_human_feedback' if role=='train' else 'human_regression_reference')
                and type(row.get('spam')) is bool and all(is_hex(row.get(k),n) for k,n in
                (('id',64),('fingerprint',64),('simhash',16))) ,'Invalid label or campaign provenance')
        require(all(type(row.get(k)) is int and row[k]>0 for k in ('observed_at','labelled_at'))
                and row['observed_at']<=row['labelled_at']<=time.time()+60,'Invalid annotation chronology')
        e=row.get('evidence')
        if not e or e.get('source')!='smtp_session':
            excluded['missing_observed_evidence']+=1;continue
        require(numeric(e.get('legacy_score')) and 0<=e['legacy_score']<=100,'Invalid legacy index')
        values,profile=vector(e)
        artifact=e.get('artifacts') or {};llm=e.get('llm') or {}
        rows.append({k:row[k] for k in ('id','fingerprint','simhash','spam','observed_at','labelled_at')}|
                    {'campaign':row['fingerprint'],'values':values,'profile':profile,
                     'legacy_score':e.get('legacy_score'),'provenance':{
                     k:artifact.get(k) for k in ('application','policy_sha256','lexical_model_sha256',
                                               'semantic_model_sha256','llm_prompt_sha256')},
                     'llm_prompt':llm.get('prompt_version') or 'unavailable'})
    require(len({r['id'] for r in rows})==len(rows),'Duplicate observation identity')
    return rows,dict(excluded),digest


def campaigns(rows, references):
    selected=[];excluded=Counter()
    for group in components(rows+references):
        own=[rows[i] for i in group if i<len(rows)]
        if not own:continue
        if len(own)!=len(group):
            excluded['protected_campaign_messages']+=len(own);continue
        if len({r['spam'] for r in own})!=1:
            excluded['conflicting_campaign_messages']+=len(own);continue
        representative=dict(min(own,key=lambda r:r['id']))
        representative['observed_at']=min(r['observed_at'] for r in own)
        representative['last_observed_at']=max(r['observed_at'] for r in own)
        representative['labelled_at']=max(r['labelled_at'] for r in own)
        selected.append(representative);excluded['duplicate_messages']+=len(own)-1
    return sorted(selected,key=lambda r:r['id']),dict(excluded)


def fit(rows, selected_features):
    y=np.array([r['spam'] for r in rows],dtype=float)
    require(len(rows)>=4 and set(y)=={0.,1.},'Both human classes required')
    x=np.array([r['values'] for r in rows])[:,selected_features]
    # Balanced corrections are not a sample of deployment class prevalence.
    sample_weights=np.array([.5/np.sum(y==v) for v in y])
    def objective(theta):
        bias,w=theta[0],theta[1:];z=bias+x@w
        residual=sample_weights*(expit(z)-y)
        loss=np.dot(sample_weights,np.logaddexp(0,z)-y*z)+RIDGE*np.dot(w,w)/2+.001*bias*bias/2
        return float(loss),np.r_[residual.sum()+.001*bias,x.T@residual+RIDGE*w]
    result=minimize(objective,np.zeros(x.shape[1]+1),jac=True,method='L-BFGS-B',
                    bounds=[(-20,20)]+[(0,20)]*x.shape[1],options={'maxiter':1000,'ftol':1e-12})
    require(result.success and np.isfinite(result.x).all(),'Evidence fitting failed')
    return result.x


def predict(model, rows, features):
    return expit(model[0]+np.array([r['values'] for r in rows])[:,features]@model[1:])


def measure(rows, probability, threshold, available=None):
    labels=np.array([r['spam'] for r in rows],dtype=int)
    available=np.ones(len(rows),dtype=bool) if available is None else np.asarray(available,dtype=bool)
    report=outcomes(labels,np.where(available,np.where(probability>=threshold,'spam','legitimate'),'review'))
    report['threshold']=threshold
    report['brier_diagnostic']=float(np.mean((probability-labels)**2)) if len(rows) else None
    report['auc']=float(roc_auc_score(labels,probability)) if len(set(labels))==2 else None
    return report


def experiment(rows, references):
    rows,excluded=campaigns(rows,references)
    require(len(rows)>=6 and min(Counter(r['spam'] for r in rows).values(),default=0)>=2
            and len({r['spam'] for r in rows})==2,'Insufficient independent campaigns')
    # Frozen ablations, fixed penalty and threshold: no search on these controls.
    variants={'content':[0,1],'content_identity':[0,1,3,4,5],
              'joint':list(range(len(FEATURES)))}
    cut=sorted(r['observed_at'] for r in rows)[int(len(rows)*.7)]
    past=[r for r in rows if r['last_observed_at']<cut and r['labelled_at']<cut]
    future=[r for r in rows if r['observed_at']>=cut]
    report={'schema':'noisefence-evidence-calibration-diagnostic-1','may_activate':False,
            'score_is_population_probability':False,'independent_validation':False,
            'sampling':'human_corrections','features':FEATURES,'ridge':RIDGE,'exclusions':excluded,
            'campaigns':len(rows),'labels':dict(Counter('spam' if r['spam'] else 'legitimate' for r in rows)),
            'llm_prompts':dict(Counter(r['llm_prompt'] for r in rows)),
            'detector_cohorts':len({json.dumps(r['provenance'],sort_keys=True) for r in rows}),
            'historical_index':measure(rows,np.array([r['legacy_score']/100 for r in rows]),.95),
            'variants':{},'limitations':[
                'Corrections are biased and these results do not estimate population performance.',
                'Historical detector cohorts and LLM prompts differ; transfer to current traffic is unqualified.',
                'Regression references stay out of fitting, but have been examined previously.',
                '0.5 is a fixed diagnostic boundary, not an approved production threshold.',
                'Campaign-out validation can train on later mail; chronological evaluation is reported separately.',
                'Missing results provide no evidence; unseen availability profiles are counted explicitly.',
                'This report is not a loadable quality or fusion model.']}
    for name,features in variants.items():
        oof=[];available=[]
        for i,row in enumerate(rows):
            model=fit(rows[:i]+rows[i+1:],features)
            oof.append(float(predict(model,[row],features)[0]))
            available.append(bool(np.any(model[1:]>1e-10)))
        model=fit(rows,features)
        entry={'campaign_out':measure(rows,np.array(oof),.5,available),
               'coefficients':{'bias':float(model[0]),**{FEATURES[f]:float(v) for f,v in zip(features,model[1:])}},
               'temporal':{'training':len(past),'test':len(future),'status':'insufficient_past_labels'}}
        if len(past)>=4 and len({r['spam'] for r in past})==2 and future:
            past_model=fit(past,features)
            entry['temporal'].update(status='complete',metrics=measure(future,predict(past_model,future,features),.5,
                                        [bool(np.any(past_model[1:]>1e-10))]*len(future)))
        if references:
            entry['regression']=measure(references,predict(model,references,features),.5,
                                         [bool(np.any(model[1:]>1e-10))]*len(references))
            entry['regression']['unseen_availability_profiles']=sum(r['profile'] not in {v['profile'] for v in rows} for r in references)
        report['variants'][name]=entry
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('feedback',type=Path);p.add_argument('report',type=Path)
    p.add_argument('--references',type=Path)
    args=p.parse_args();os.umask(0o077)
    require(not args.report.exists(),'Report already exists')
    rows,counts,sha=load(args.feedback,'train')
    refs,refcounts,refsha=load(args.references,'regression') if args.references else ([],{},None)
    report=experiment(rows,refs)
    report.update(dataset_sha256=sha,references_sha256=refsha,export_exclusions=counts,
                  reference_exclusions=refcounts,trainer_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    with args.report.open('x') as f:json.dump(report,f,indent=2,allow_nan=False);f.write('\n')
    print(json.dumps({'status':'diagnostic_complete','may_activate':False,'campaigns':report['campaigns']}))


if __name__=='__main__':main()
