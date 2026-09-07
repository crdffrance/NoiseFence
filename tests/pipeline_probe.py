#!/usr/bin/env python3
"""Exercise the benchmark binary with local synthetic mail and no paid connector."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

binary = Path(sys.argv[1]).resolve(strict=True)
repository = Path(__file__).resolve().parents[1]
original = b'From: sender@example.test\r\nTo: alice@example.test\r\nSubject: private-fixture-subject\r\n\r\nPrivate fixture content that must not appear in measurements.\r\n'
with tempfile.TemporaryDirectory(prefix='noisefence-pipeline-test-') as directory:
    root = Path(directory)
    profile = root / 'config.toml'
    settings = (repository / 'config/development.toml').read_text().replace('data_dir = "var/development"', 'data_dir = ' + json.dumps(str(root / 'state')))
    profile.write_text(settings)
    (root / 'message.eml').write_bytes(original)
    cases = [{'id':'synthetic', 'path':'message.eml', 'source_ip':'192.0.2.1', 'helo':'sender.example.test', 'mail_from':'sender@example.test'}]
    manifest = root / 'cases.json'
    manifest.write_text(json.dumps(cases))

    def run(output, *arguments):
        return subprocess.run([str(binary), '--config', str(profile), '--cases', str(manifest), '--output', str(root / output), '--iterations', '3', '--warmup', '1', '--interval-ms', '0', *arguments], capture_output=True, text=True, timeout=15)

    success = run('success.jsonl')
    assert success.returncode == 0, success.stderr
    rows = [json.loads(line) for line in (root / 'success.jsonl').read_text().splitlines()]
    assert rows[0]['record'] == 'configuration' and rows[0]['paid_llm'] is False
    trials = [r for r in rows if r['record'] == 'trial']
    assert len(trials) == 4 and sum(r['warmup'] for r in trials) == 1
    summary = rows[-1]
    assert summary['record'] == 'summary' and summary['run_finished'] and not summary['sent']
    case = summary['cases'][0]
    assert case['complete'] == 3 and case['errors'] == case['incomplete'] == 0
    measured = sorted(r['elapsed_us'] for r in trials if not r['warmup'])
    assert case['all_trials']['samples'] == 3
    assert case['all_trials']['p50_us'] == measured[1]
    assert case['all_trials']['p95_us'] == measured[2]
    payload = (root / 'success.jsonl').read_bytes()
    for private in [b'private-fixture-subject', b'Private fixture content', b'"features":', b'"body":']:
        assert private not in payload
    assert not (root / 'state').exists(), 'benchmark created queue or delivery state'
    assert (root / 'message.eml').read_bytes() == original
    assert run('success.jsonl').returncode != 0
    assert (root / 'success.jsonl').read_bytes() == payload

    # A failed local scanner remains in the measurements; a fast failure is not success.
    profile.write_text(settings + '\n[antivirus]\nsocket = ' + json.dumps(str(root / 'absent.sock')) + '\ntimeout_ms = 100\n')
    failure = run('incomplete.jsonl')
    assert failure.returncode == 0, failure.stderr
    summary = json.loads(failure.stdout)
    case = summary['cases'][0]
    assert case['incomplete'] == 3 and case['complete'] == 0 and case['errors'] == 0
    assert case['all_trials']['samples'] == 3 and case['complete_trials_only'] is None
    assert case['statuses']['antivirus:unavailable'] == 3

    # Refuse costly analysis before key lookup, model loading or output creation.
    profile.write_text(settings + '''
[llm]
project_id = "00000000-0000-0000-0000-000000000000"
model = "test-only"
api_key_env = "NOISEFENCE_UNUSED_TEST_KEY"
monthly_budget_micro_eur = 1000000
input_micro_eur_per_million = 150000
output_micro_eur_per_million = 350000
pricing_checked_at = 0
''')
    denied = run('paid.jsonl')
    assert denied.returncode != 0 and '--allow-paid-llm' in denied.stderr
    assert not (root / 'paid.jsonl').exists() and not (root / 'state').exists()
    profile.write_text(settings)
    cases.append(cases[0])
    manifest.write_text(json.dumps(cases))
    assert run('duplicate.jsonl').returncode != 0
    assert not (root / 'duplicate.jsonl').exists()

print(json.dumps({'status':'passed', 'warmup_excluded':True, 'failures_retained':True, 'private_content_omitted':True, 'overwrite_refused':True, 'paid_calls_require_flag':True, 'duplicate_cases_refused':True, 'queue_created':False, 'sent':False}))
