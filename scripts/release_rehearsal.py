#!/usr/bin/env python3
"""Fetch a pinned public baseline and publish only anonymous lifecycle evidence."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from version import cargo_version

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'deploy/postgresql'))
import release_bundle as bundle
from release_version import precedence
sys.path.pop(0)

BASELINE = ROOT/'tests/fixtures/release-baseline.json'


def baseline():
    value = json.loads(BASELINE.read_text(), object_pairs_hook=bundle.pairs)
    bundle.require(value.get('schema') == 'noisefence-release-baseline-1'
        and set(value.get('archives', {})) == set(bundle.MACHINES), 'Invalid rehearsal baseline')
    for platform, digest in value['archives'].items():
        bundle.identity(value['version'], platform, value['commit'])
        bundle.require(isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest),
                       'Invalid baseline archive checksum')
    return value


def baseline_name(pin, platform):
    return bundle.identity(pin['version'], platform, pin['commit'])+'.tar.gz'


def fetch_baseline(platform, directory):
    pin = baseline(); name = baseline_name(pin, platform)
    directory = Path(directory).resolve(); directory.mkdir(mode=0o700)
    environment = {**os.environ, 'GH_HOST': 'github.com', 'GH_PROMPT_DISABLED': '1'}
    bundle.bounded_command(['gh', 'release', 'download', 'v'+pin['version'],
        '--repo', bundle.REPOSITORY, '--pattern', name, '--dir', str(directory)],
        timeout=180, maximum=65536, env=environment)
    archive = directory/name
    bundle.require(bundle.digest(archive) == pin['archives'][platform],
                   'Downloaded baseline differs from the reviewed checksum')
    bundle.inspect_archive(archive, pin['version'], platform, pin['commit'])
    # This baseline predates attestations; a reviewed checksum pin is only a
    # fixture dependency, never a substitute for new-release provenance.
    Path(str(archive)+'.sha256').write_text(pin['archives'][platform]+'  '+name+'\n')
    return archive


def read_report(path):
    with Path(path).open('rb') as source: raw = source.read(8*1024**2+1)
    bundle.require(len(raw) <= 8*1024**2, 'Lifecycle report exceeds bounds')
    value = json.loads(raw, object_pairs_hook=bundle.pairs)
    bundle.require(isinstance(value, dict) and value.get('status') == 'passed'
                   and value.get('production_affected') is False, 'Lifecycle did not pass in isolation')
    return value


def confinement_summary(directory, paired, files):
    name = paired.get('apparmor_profile')
    evidence = Path(directory)/'apparmor/confinement.json'
    if not name:
        bundle.require(not evidence.exists() and paired.get('confinement_scope') in (None, 'not_exercised'),
                       'Unexpected confinement evidence without an enforced pair')
        return {'status':'not_exercised'}
    bundle.require(isinstance(name,str) and re.fullmatch(r'noisefence-test-[a-f0-9]{12}',name)
        and paired.get('confinement_scope') == 'named_profile_enforcement_with_dac_canary',
        'Unexpected confinement scope')
    proof = read_report(evidence)
    bundle.require(proof.get('schema') == 'noisefence-confinement-rehearsal-1'
        and proof.get('profile') == name and proof.get('profile_removed') is True
        and proof.get('platform') == paired.get('platform'),
        'Confinement load or cleanup is not bound to this paired run')
    for field in ('profile_sha256','generator_sha256','renderer_sha256'):
        bundle.require(isinstance(proof.get(field),str) and re.fullmatch('[0-9a-f]{64}',proof[field]),
                       'Missing confinement source digest')
    bundle.require(proof['generator_sha256'] == files.get('deploy/hardening/isolation.py'),
                   'Test policy generator differs from the candidate archive')
    def runtime(row):
        return (row.get('profile') == name and row.get('process_profile') == name+' (enforce)'
                and row.get('mode') == 'enforce' and row.get('binary_sha256') == files['noisefence'])
    events = paired.get('checks',[])
    for node in ('mx1','mx2'):
        bundle.require(any(row.get('check') == 'apparmor_canary_enforced' and row.get('node') == node
            and row.get('profile') == name and all(row.get(key) is True for key in
                ('allowed_configuration','unconfined_canary_read','confined_canary_denied')) for row in events),
            'Both nodes need a real confinement canary')
        bundle.require(any(row.get('check') == 'candidate_apparmor_enforced' and row.get('node') == node
            and runtime(row) for row in events), 'Both validation candidates need runtime confinement')
        bundle.require(runtime(paired.get('final_running',{}).get(node,{}).get('confinement',{})),
                       'Both final daemons need runtime confinement')
    return {'status':'enforced', 'mode':'enforce', 'profile_removed':True,
            **{key:proof[key] for key in ('profile_sha256','generator_sha256','renderer_sha256')}}


def summarize(platform, archive, directory, *, version, commit):
    pin = baseline(); directory = Path(directory); archive = Path(archive)
    bundle.require(precedence(pin['version']) < precedence(version), 'Review the baseline before changing release order')
    inspected = bundle.inspect_archive(archive, version, platform, commit)
    actual = bundle.digest(archive)
    bundle.require(Path(str(archive)+'.sha256').read_text().strip() == actual+'  '+archive.name,
                   'Candidate outer checksum differs')
    old = directory/'baseline'/baseline_name(pin, platform)
    bundle.require(bundle.digest(old) == pin['archives'][platform], 'Baseline changed during rehearsal')
    expected = {pin['version']:pin['archives'][platform], version:actual}
    standalone = read_report(directory/'standalone/lifecycle-report.json')
    paired = read_report(directory/'paired/paired-lifecycle-report.json')
    for report in [standalone, paired]:
        bundle.require(report.get('platform') == platform.replace('-', '/', 1)
                       and report.get('archive_sha256') == expected,
                       'Lifecycle reports do not describe these exact archives')
    bundle.require(standalone.get('versions') == [pin['version'], version], 'Wrong standalone release order')
    bundle.require(standalone.get('cleanup') is True, 'Standalone fixture cleanup is unverified')
    bundle.require(paired.get('cleanup') is True and paired.get('candidate_mode') == 'exact_archive'
        and paired.get('archive_commits') == {pin['version']:pin['commit'], version:commit},
        'Exact paired candidate or cleanup is unverified')
    helpers = {str(Path(name).relative_to('deploy/postgresql')): digest
               for name, digest in inspected['files'].items() if name.startswith('deploy/postgresql/')}
    bundle.require({'upgrade_validation.py','upgrade_activation.py','upgrade_exchange.py'} <= set(helpers)
        and paired.get('installed_helper_sha256') == {'mx1':helpers, 'mx2':helpers},
        'Installed native helpers must match the candidate archive')
    candidate = paired.get('validation_candidate', {})
    bundle.require(candidate.get('origin') == 'exact_archive'
        and candidate.get('version') == version and candidate.get('commit') == commit
        and candidate.get('archive_sha256') == actual
        and candidate.get('binary_sha256') == inspected['files']['noisefence']
        and candidate.get('build_sha256') == inspected['files']['build.json']
        and candidate.get('manifest_sha256') == inspected['files']['SHA256SUMS'],
        'Paired runtime is not bound to the inspected candidate')
    running = paired.get('final_running', {})
    bundle.require(set(running) == {'mx1', 'mx2'} and all(
        row.get('smtp_ready') is True and row.get('running_release') == version
        and row.get('binary_sha256') == inspected['files']['noisefence']
        for row in running.values()), 'Both exact candidate runtimes must finish ready')
    accepted = paired.get('accepted', [])
    bundle.require(len(accepted) >= 24 and len({row['id'] for row in accepted}) == len(accepted)
                   and {row['node'] for row in accepted} == {'mx1', 'mx2'},
                   'Native lifecycle mail acceptance coverage is missing')
    checks = sorted({row['check'] for row in paired['checks']})
    required = {'candidate_expired_stopped_and_preserved_selected_data',
        'candidate_peer_loss_invalidates_readiness', 'mandatory_peer_outage_deferred',
        'committed_start_failure_recovered_forward_and_auxiliary_jobs_held',
        'actual_ssh_completion_reply_lost_after_durable_finish',
        'native_pair_completed_over_pinned_ssh_after_proof_expiry',
        'normal_candidates_verified_and_operation_completed'}
    bundle.require(required <= set(checks), 'Required native recovery coverage is missing')
    standalone_checks = {'fresh_install_'+pin['version'], 'synthetic_smtp_acceptance',
        'upgrade_'+version, 'idempotent_reinstall',
        'stopped_service_preserves_accepted_body_and_queue', 'unit_removed_data_retained',
        'disk_full_before_mail_temporarily_rejected', 'disk_full_after_data_temporarily_rejected',
        'disk_full_recovery_preserves_accepted_messages'}
    bundle.require(standalone_checks <= set(standalone['checks']), 'Standalone lifecycle coverage is missing')
    confinement = confinement_summary(directory, paired, inspected['files'])
    # Deliberate allowlist: no fixture credentials, messages, recipients, private
    # paths, raw observations, environment values or journal text in CI artifacts.
    return {'schema':'noisefence-release-rehearsal-1', 'status':'passed',
        'platform':platform, 'version':version, 'commit':commit,
        'archive_sha256':actual, 'binary_sha256':inspected['files']['noisefence'],
        'baseline':{'version':pin['version'], 'commit':pin['commit'], 'sha256':pin['archives'][platform]},
        'standalone_checks':standalone['checks'], 'paired_checks':checks,
        'accepted_synthetic_messages':len(accepted), 'cleanup':True,
        'production_affected':False, 'provenance_verified':False,
        'rehearsal_only':inspected['rehearsal_only'], 'confinement':confinement,
        'not_qualified':paired['not_qualified']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['baseline-version', 'fetch', 'summarize'])
    parser.add_argument('--platform', choices=list(bundle.MACHINES))
    parser.add_argument('--directory', type=Path)
    parser.add_argument('--archive', type=Path)
    args = parser.parse_args(); os.umask(0o077)
    if args.action == 'baseline-version':
        print(baseline()['version']); return
    if args.platform is None or args.directory is None:
        parser.error('--platform and --directory are required')
    if args.action == 'fetch':
        print(fetch_baseline(args.platform, args.directory)); return
    if args.archive is None: parser.error('--archive is required for summarize')
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    result = summarize(args.platform, args.archive, args.directory, version=cargo_version(), commit=commit)
    path = args.directory/'qualification.json'
    with path.open('x') as output: output.write(json.dumps(result, indent=2)+'\n')
    print(json.dumps(result))


if __name__ == '__main__': main()
