import test from 'node:test';
import assert from 'node:assert/strict';
import { comparisonLabel, comparisonPoints, agreementRate } from '../app/rspamd-format.ts';

test('Rspamd keeps signed points and absent results are never displayed as zero', () => {
  assert.equal(comparisonPoints(-3.2), '-3.20');
  assert.equal(comparisonPoints(143.12), '143.12');
  for (const value of [null, undefined, NaN, Infinity]) assert.equal(comparisonPoints(value), '—');
  assert.equal(comparisonLabel(null), 'Not compared');
  assert.equal(comparisonLabel({ status: 'timeout', comparison: 'agreement' }), 'Comparison timed out');
  assert.equal(comparisonLabel({ status: 'complete', comparison: 'inconclusive' }), 'No comparable verdict');
});
test('agreement excludes missing and inconclusive verdicts from its denominator', () => {
  assert.equal(agreementRate({ total: 100, completed: 40, agreements: 15, disagreements: 5, inconclusive: 20, pending: 3 }), '75.0%');
  assert.equal(agreementRate({ total: 100, completed: 0, agreements: 0, disagreements: 0, inconclusive: 0, pending: 10 }), '—');
});
