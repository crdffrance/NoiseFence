#!/usr/bin/env python3
"""A fixed, offline entry point for the Web research worker; data files only."""
import argparse,json,os
from pathlib import Path
from train_quality import train
from compare_quality import compare
from evaluate_quality import evaluate


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('dataset',type=Path);p.add_argument('directory',type=Path)
    p.add_argument('--operation',choices=('train','compare','evaluate'),required=True)
    p.add_argument('--candidate',type=Path)
    a=p.parse_args();os.umask(0o077)
    if a.directory.exists():raise ValueError('Research output already exists')
    a.directory.mkdir(mode=0o700)
    if a.operation=='train':
        try:
            report=train(a.dataset,a.directory/'candidate','quality-'+a.directory.name)
        except ValueError as error:
            reasons={'Detector artifacts changed inside this sample; evaluate separately':'mixed_detector_cohorts',
                     'Only explicit development samples may be fitted':'evaluation_sample_cannot_train'}
            report={'status':'failed','error_code':reasons.get(str(error),'invalid_training_data'),
                    'may_activate':False,'observation_only':True}
    elif a.operation=='compare':report=compare(a.dataset)
    else:
        if a.candidate is None:raise ValueError('Candidate required')
        report=evaluate(a.dataset,a.candidate/'model.json',a.candidate/'training-manifest.json')
    # Reports contain aggregate counters and provenance, never per-message text.
    report.pop('sampling',None)  # the private training manifest retains provenance
    with (a.directory/'report.json').open('x') as f:
        json.dump(report,f,allow_nan=False);f.flush();os.fsync(f.fileno())
    print(json.dumps({'status':report.get('status','complete')}))

if __name__=='__main__':main()
