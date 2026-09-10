#!/usr/bin/env python3
"""Verify research coverage accounting through a real isolated SMTP daemon."""
import json
from pathlib import Path
import subprocess
import sys

binary = Path(sys.argv[1]).resolve(strict=True)
root = Path(sys.argv[2]).resolve()
root.mkdir(mode=0o700, parents=True, exist_ok=False)
repository = Path(__file__).resolve().parents[1]

def run(name, *options):
    output = root / name
    with (root / (name + '.log')).open('xb') as log:
        result = subprocess.run([sys.executable, str(repository / 'scripts/smtp_load.py'),
                                 '--binary', str(binary), '--output-dir', str(output),
                                 '--require-complete', *options],
                                stdout=log, stderr=subprocess.STDOUT, timeout=120)
    report = json.loads((output / 'summary.json').read_text())
    assert report['schema'] == 'noisefence-smtp-load-2'
    assert report['run_finished'] and report['correctness_passed'], report
    assert report['missing'] == report['extra'] == report['duplicates'] == report['changed_bodies'] == 0
    return result.returncode, report

code, good = run('documents', '--messages', '8', '--concurrency', '4', '--processing', '4',
                 '--message-bytes', '8192', '--attachments')
assert code == 0 and good['requirements_met'] and good['complete'] == 8, good
assert good['statuses']['heuristics'] == good['statuses']['content_inspection'] == {'complete': 8}
for component, findings in [('heuristics', ['fr.credentials', 'en.credentials']),
                            ('content_inspection', ['html_event_handler', 'pdf_active_name'])]:
    assert all(good['research']['findings'][component][finding] == 8 for finding in findings), good

# The primary scan still succeeds when the advisory heuristic input limit is
# exceeded. A complete-analysis performance claim must include that limitation.
code, limited = run('limited', '--messages', '2', '--concurrency', '1', '--processing', '1',
                    '--message-bytes', '1048576', '--research')
assert code == 1 and not limited['requirements_met'], limited
assert limited['primary_complete'] == limited['accepted'] == limited['delivered'] == 2
assert limited['complete'] == 0 and limited['incomplete'] == 2
assert limited['statuses']['heuristics'] == {'limited': 2}
assert limited['research']['heuristic_limits'], limited
print(json.dumps({'research_smtp_cases_passed': 2, 'delivered': 10,
                  'limited_analyses_explicit': 2, 'body_changes': 0}))
