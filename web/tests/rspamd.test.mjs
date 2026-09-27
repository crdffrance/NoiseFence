import test from 'node:test';
import assert from 'node:assert/strict';
import { comparisonLabel, comparisonExplanation, comparisonPoints, agreementRate } from '../app/rspamd-format.ts';

test('Rspamd keeps signed points and absent results are never displayed as zero', () => {
  assert.equal(comparisonPoints(-3.2), '-3.20');
  assert.equal(comparisonPoints(143.12), '143.12');
  for (const value of [null, undefined, NaN, Infinity]) assert.equal(comparisonPoints(value), '—');
  assert.equal(comparisonLabel(null), 'Not compared');
  assert.equal(comparisonLabel({ status: 'timeout', comparison: 'agreement' }), 'Comparison timed out');
  assert.equal(comparisonLabel({ status: 'complete', comparison: 'inconclusive' }), 'Second opinion recorded');
});
test('agreement excludes missing and inconclusive verdicts from its denominator', () => {
  assert.equal(agreementRate({ total: 100, completed: 40, agreements: 15, disagreements: 5, inconclusive: 20, pending: 3 }), '75.0%');
  assert.equal(agreementRate({ total: 100, completed: 0, agreements: 0, disagreements: 0, inconclusive: 0, pending: 10 }), '—');
});

test('deferral is a recorded second opinion, never a pending NoiseFence verdict', () => {
  for (const action of ['greylist', 'soft reject']) {
    const report = {status: 'complete', comparison: 'inconclusive', action, score: 4.8, required_score: 15};
    assert.equal(comparisonLabel(report), 'Rspamd proposes deferral');
    assert.match(comparisonExplanation(report), /not executed/);
    assert.match(comparisonExplanation(report), /excluded from binary/);
  }
  assert.match(comparisonExplanation({status:'complete',comparison:'inconclusive',action:'custom'}), /does not make the NoiseFence decision pending/);
  for (const status of ['pending','timeout','unavailable']) {
    assert.match(comparisonExplanation({status}), /never changes the NoiseFence verdict or delivery/);
  }
});
