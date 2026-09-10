#!/usr/bin/env python3
"""Compare trusted worker revisions on public synthetic OCR/QR images and PDFs.

Linux with Pillow, qrencode, DejaVu fonts and the worker decoder dependencies.
Run in a private, resource-limited test unit; never point this tool at mail data.
"""
import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import statistics
import time

ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compare(args):
    paths = {'baseline': args.baseline_worker.resolve(strict=True),
             'candidate': args.candidate_worker.resolve(strict=True)}
    if not 1 <= args.pairs <= 32 or not all(p.is_file() and p.stat().st_size <= 1024*1024 for p in paths.values()):
        raise ValueError('Invalid pair count or trusted worker file')
    out = args.output_dir.resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {'schema': 'noisefence-vision-comparison-1', 'run_finished': False,
              'scope': 'Alternating supervisor/job calls on public synthetic fixtures; excludes SMTP, Rust IPC and ML. Resource limits belong to the caller. No filtering-quality claim.',
              'workers_sha256': {name: digest(path) for name, path in paths.items()},
              'probe_sources_sha256': {name: digest(ROOT/name) for name in
                                       ['scripts/vision_compare.py', 'tests/vision_worker.py']},
              'pairs_per_case': args.pairs, 'records': []}
    report['output_comparison_fields'] = ['protocol', 'status', 'pages', 'errors']
    try:
        workers = {name: module('comparison_'+name, path) for name, path in paths.items()}
        fixtures = module('comparison_fixtures', ROOT/'tests/vision_worker.py')
        image, payload = fixtures.fixture(out)
        inputs = {'image': fixtures.request(image),
                  'pdf': fixtures.request(out/'synthetic.pdf', 'pdf')}
        report['fixtures_sha256'] = {p.name: digest(p) for p in [image, out/'synthetic.pdf']}
        reference = {}
        for case, req in inputs.items():
            raw = json.dumps(req).encode()
            for index in range(args.pairs):
                order = ['baseline', 'candidate'] if index % 2 == 0 else ['candidate', 'baseline']
                for name in order:
                    started = time.monotonic()
                    response = json.loads(workers[name].supervise(raw, 'synthetic-comparison'))
                    elapsed = (time.monotonic()-started)*1000
                    if (response['status'] != 'complete' or len(response['pages']) != 1
                            or len(response['pages'][0]['codes']) != 1
                            or response['pages'][0]['codes'][0]['data'] != payload
                            or len(response['pages'][0]['text']) < 80):
                        raise ValueError('Incomplete or incorrect public OCR/QR fixture')
                    selected = {k: response[k] for k in report['output_comparison_fields']}
                    fingerprint = hashlib.sha256(json.dumps(selected, sort_keys=True).encode()).hexdigest()
                    expected = reference.setdefault(case, fingerprint)
                    report['records'].append({'case': case, 'iteration': index, 'worker': name,
                                              'wall_ms': elapsed, 'response_sha256': fingerprint})
                    if fingerprint != expected:
                        raise ValueError('Worker outputs differ on the public fixture')
        if report['workers_sha256'] != {name: digest(path) for name, path in paths.items()}:
            raise ValueError('Worker source changed during comparison')
        summary = {}
        for case in inputs:
            summary[case] = {}
            for name in workers:
                values = sorted(r['wall_ms'] for r in report['records']
                                if r['case'] == case and r['worker'] == name)
                summary[case][name] = {'n': len(values), 'median_ms': statistics.median(values),
                                       'p95_ms': values[math.ceil(.95*len(values))-1]}
        report.update(run_finished=True, complete_outputs_equal=True, summary=summary,
                      quantiles='Median averages the central pair; p95 uses nearest rank.')
    except Exception as error:
        report['failure_kind'] = type(error).__name__
        raise
    finally:
        (out/'report.json').write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps(report['summary'], indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline-worker', type=Path, required=True)
    parser.add_argument('--candidate-worker', type=Path, default=ROOT/'deploy/vision-worker.py')
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--pairs', type=int, default=8)
    compare(parser.parse_args())
