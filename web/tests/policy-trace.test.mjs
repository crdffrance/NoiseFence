import assert from 'node:assert/strict';
import test from 'node:test';
import {
  orderingDescription,
  thresholdSource,
  traceOutcome,
  sampleChange,
} from '../app/policy-trace.ts';

test('trace explains the recorded threshold owner, not the selected action profile', () => {
  const trace = {
    threshold_locked: false,
    threshold_profile: 'domain',
    profiles: [
      {
        id: 'mailbox',
        name: 'Personal actions',
        scope: 'alice@example.test',
        selected: true,
        threshold: null,
      },
      {
        id: 'domain',
        name: 'Domain threshold',
        scope: '*@example.test',
        selected: false,
        threshold: 98,
      },
    ],
  };
  assert.equal(thresholdSource(trace), 'Domain threshold (*@example.test)');
  assert.match(
    thresholdSource({ ...trace, threshold_locked: true }),
    /detector decision/,
  );
  assert.equal(
    thresholdSource({ ...trace, threshold_profile: null }),
    'Global filter threshold',
  );
  assert.equal(
    thresholdSource({ ...trace, profiles: [] }),
    'Recorded source unavailable',
  );
});
test('unknown facts and unrecorded actions never appear as unchanged comparisons', () => {
  assert.equal(
    sampleChange({ status: 'not_available' }),
    'Not available for this recipient',
  );
  assert.equal(
    sampleChange({ status: 'simulated', comparable: false, changed: null }),
    'Comparison incomplete',
  );
  assert.equal(
    sampleChange({ status: 'simulated', comparable: true, changed: false }),
    'Unchanged',
  );
  assert.equal(
    sampleChange({ status: 'simulated', comparable: true, changed: true }),
    'Would change',
  );
  assert.equal(traceOutcome('stopped'), 'Skipped after stop');
  assert.equal(traceOutcome('missing_facts'), 'Missing facts');
  assert.match(orderingDescription(undefined), /Legacy ordering/);
  assert.match(
    orderingDescription('scoped'),
    /Personal rules cannot stop administrator/,
  );
});
