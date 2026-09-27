import test from 'node:test';
import assert from 'node:assert/strict';
import { observationState, observationRole, observationResult, observationMeasurement,
  observationName, observationScope, sharedObservationGroups } from '../app/observations-format.ts';

const record = {id:'crdf.0',scope:'host_lookup',state:'complete',exclusion:null,
  result:{kind:'reputation',value:'not_listed'}};

test('normalised observations distinguish missing checks from safe results', () => {
  const labels = ['complete','partial','unavailable','timeout','budget_exceeded','disabled','not_applicable'].map(observationState);
  assert.equal(new Set(labels).size, 7);
  assert.match(observationResult(record), /Not listed.*safety not established/);
  assert.equal(observationResult({...record,state:'timeout'}),'No usable verdict');
  assert.match(observationResult({...record,exclusion:'unsupported_claims'}), /not supported/);
  assert.equal(observationResult({...record,result:null}),'No verdict recorded');
  assert.equal(observationScope('host_lookup'),'Host-root lookup');
  assert.equal(observationScope('url_navigation'),'URL navigation');
});

test('native points and LLM self-reported values never become a percent risk index', () => {
  assert.equal(observationMeasurement('retained',{value:1,unit:'points'}),'After caps: 1 points');
  assert.match(observationMeasurement('reported_probability',{value:0.99,unit:'reported_probability'}),/0.99 self-reported, 0–1/);
  assert.match(observationMeasurement('contribution',{value:1.5,unit:'log_odds'}),/log-odds/);
  for (const m of [{value:NaN,unit:'points'},{value:1.1,unit:'reported_probability'},{value:50,unit:'percent'}])
    assert.equal(observationMeasurement('raw',m),'Value not recorded');
  assert.equal(observationRole('comparison'),'Comparison only');
  assert.equal(observationRole('admission'),'SMTP admission only');
});

test('authentication absence and shared observations retain their specific meaning', () => {
  assert.equal(observationResult({...record,id:'dkim',result:{kind:'authentication',value:[]}}),'No signatures found');
  assert.equal(observationResult({...record,id:'spf',result:{kind:'authentication',value:['pass']}}),'Pass');
  const groups = [{key:'host:abc',observations:['crdf.0','virustotal.0']},{key:'single',observations:['vision']}];
  assert.deepEqual(sharedObservationGroups({groups}),[groups[0]]);
  assert.equal(observationName('native.llm'),'Native · LLM');
  assert.equal(observationName('dqs.domain.2'),'Spamhaus · domain 3');
  assert.equal(observationName('private-zone-canary'),'Other recorded detector');
});

test('provider exclusions explain deduplication, conflict and frozen-time eligibility', () => {
  for (const [exclusion, expected] of [
    ['duplicate_target', /counted once/], ['conflicting_target', /same provider/],
    ['missing_capture_time', /completion time not recorded/], ['invalid_observation_time', /captured analysis window/],
    ['stale_result', /Stale/],
  ]) assert.match(observationResult({...record, exclusion}), expected);
});
