#!/usr/bin/env python3
"""Compare recorded engines against human labels, without retraining or network I/O."""
from collections import Counter
import math
from train_quality import load_dataset, read_jsonl, components, readiness, partition
from quality_metrics import outcomes, metrics
from evaluate_quality import baseline
from recorded_decisions import engine_decision, engine_outcome, policy_report, raw_score


def rspamd_outcome(row):
    report=row.get('rspamd') or {}
    if report.get('status')!='complete':return 'review'
    return {'no action':'legitimate','accept':'legitimate','reject':'spam',
            'add header':'spam','rewrite subject':'spam'}.get(report.get('action'),'review')


def paired_comparison(rows):
    """Compare identical human-labelled observations; missing is not a prediction."""
    labelled=[r for r in rows if r.get('risk') in ('legitimate','spam')]
    native_present=lambda r:engine_decision(r) is not None
    other_present=lambda r:(r.get('rspamd') or {}).get('status')=='complete'
    paired=[r for r in labelled if native_present(r) and other_present(r)]
    def measure(group):
        labels=[int(r['risk']=='spam') for r in group]
        return {'messages':len(group),'baseline':outcomes(labels,[engine_outcome(r) for r in group]),
                'rspamd':outcomes(labels,[rspamd_outcome(r) for r in group])}
    # Group before pairing: a conflicting label in a missing-analysis row
    # must not disappear and leave its campaign looking consistently labelled.
    identified=[dict(r,campaign=r['fingerprint']) for r in labelled if r.get('fingerprint') and r.get('simhash')]
    representatives=[];conflicts=0
    for indexes in components(identified):
        group=[identified[i] for i in indexes]
        if len({r['risk'] for r in group})>1:
            conflicts+=1;continue
        eligible=[r for r in group if native_present(r) and other_present(r)]
        if eligible:representatives.append(min(eligible,key=lambda r:(r['observed_at'],r['id'])))
    result=measure(paired)
    result['coverage']={'labelled':len(labelled),'paired':len(paired),
        'native_missing':sum(not native_present(r) for r in labelled),
        'rspamd_missing':sum(not other_present(r) for r in labelled),
        'paired_legitimate':sum(r['risk']=='legitimate' for r in paired),
        'paired_spam':sum(r['risk']=='spam' for r in paired),
        'paired_core_incomplete':sum((engine_decision(r) or {}).get('complete',r.get('baseline_complete')) is False for r in paired),
        'campaign_identity_missing':sum(not r.get('fingerprint') or not r.get('simhash') for r in paired)}
    result['campaigns']={**measure(representatives),'count':len(representatives),'conflicting':conflicts}
    result['outcome_pairs']=[{'noisefence':a,'rspamd':b,'messages':n} for (a,b),n in sorted(
        Counter((engine_outcome(r),rspamd_outcome(r)) for r in paired).items())]
    result['availability_by_label']={risk:dict(Counter(
        (r.get('rspamd') or {}).get('status') or 'missing' for r in labelled if r['risk']==risk))
        for risk in ('legitimate','spam')}
    # The native artifact digest also binds the application and decision policy.
    result['profiles']=[{'native':native,'rspamd':other,'messages':n} for (native,other),n in sorted(Counter(
        (((r.get('quality') or {}).get('artifacts_sha256') or 'missing'),
         ((r.get('rspamd') or {}).get('settings_sha256') or 'missing')) for r in paired).items())]
    result['capture_comparison_supported']=result['coverage']['paired_spam']>=20
    result['independent_validation']=False
    return result


def compare(dataset):
    header,usable,coverage,_,digest=load_dataset(dataset,allow_multiple_artifacts=True)
    records,again=read_jsonl(dataset)
    if digest!=again:raise ValueError('Dataset changed during comparison')
    rows=records[1:-1]
    labelled=[r for r in rows if r.get('risk') in ('legitimate','spam')]
    y=[int(r['risk']=='spam') for r in labelled]
    native=[baseline(r) for r in labelled];other=[rspamd_outcome(r) for r in labelled]
    scored=[r for r in labelled if raw_score(r) is not None]
    lexical=metrics([int(r['risk']=='spam') for r in scored],[raw_score(r)/100 for r in scored],.05,.95)
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
    report={'schema':'noisefence-quality-comparison-3','dataset_sha256':digest,'purpose':header.get('purpose','regression'),'sampling':header['sampling'],
      'paired':paired_comparison(rows),'recorded_policy':policy_report(rows),'evaluation_scope':'recorded_engines_with_separate_policy_results',
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
        'Paired results use recorded engine verdicts on the same labelled messages; recipient overrides are excluded.',
        'Population totals retain missing analyses as review for coverage accounting, not a head-to-head accuracy claim.',
        'Recorded policy actions are receipt-time intentions, not delivery confirmations; observation can suppress requested actions.',
        'Rows are stored records and may include recipient-policy variants; campaign grouping does not certify independent arrivals.',
        'Greylisting and custom Rspamd actions are non-final decisions, not spam detections.',
        'Incomplete core coverage does not erase a recorded threat verdict; enforcement remains a separate policy.',
        'Fewer than 20 paired human-labelled spams cannot support a useful capture comparison; more data and confidence bounds remain necessary.',
        'Message intervals assume independent observations; also inspect campaign metrics.',
        'A previously examined sample is a regression set, not independent qualification.',
        'Recorded total latency cannot establish native warm-cache performance.']}
    for kind in ('conversation','transactional','notification','newsletter','promotion','other',None):
        group=[r for r in labelled if r.get('kind')==kind];labels=[int(r['risk']=='spam') for r in group]
        report['slices'][kind or 'unlabelled_type']={'baseline':outcomes(labels,[baseline(r) for r in group]),'rspamd':outcomes(labels,[rspamd_outcome(r) for r in group])}
    return report
