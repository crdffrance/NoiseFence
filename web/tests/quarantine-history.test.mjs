import assert from 'node:assert/strict';
import test from 'node:test';
import {
  holdState,
  requestSummary,
  receiptAwaitingState,
} from '../app/quarantine-history.ts';
const held = {
  address: 'alex@example.test',
  status: 'quarantined',
  held_until: 200,
  pending_command: null,
};
const request = {
  action: 'release',
  result: 'pending',
  execution_result: null,
  expires_at: 200,
};
test('quarantine action eligibility respects expiry even before cleanup and pending commands', () => {
  assert.equal(holdState(held, 199), 'held');
  assert.equal(holdState(held, 200), 'elapsed');
  assert.equal(
    holdState({ ...held, pending_command: 'command' }, 199),
    'pending',
  );
  assert.equal(
    holdState({ ...held, pending_command: 'command' }, 200),
    'elapsed',
  );
  for (const held_until of [null, undefined, NaN, Infinity])
    assert.equal(holdState({ ...held, held_until }, 100), 'unknown');
  for (const status of [
    'pending',
    'delivered',
    'discarded',
    'expired',
    'failed',
  ])
    assert.equal(holdState({ ...held, status }, 300), 'resolved');
});
test('request expiry and revocation never claim the operation did not run', () => {
  assert.match(requestSummary(request, 199), /Awaiting an execution receipt/);
  assert.match(requestSummary(request, 200), /does not prove.*never ran/);
  assert.match(
    requestSummary({ ...request, result: 'expired' }, 100),
    /does not prove.*never ran/,
  );
  assert.match(
    requestSummary({ ...request, result: 'revoked' }, 100),
    /No execution receipt/,
  );
  assert.match(
    requestSummary({ ...request, result: 'unknown' }, 100),
    /No comparable execution receipt/,
  );
});
test('late receipts are explicit and cannot be confused with recipient-server acceptance', () => {
  for (const result of ['expired', 'revoked'])
    for (const action of ['release', 'delete'])
      assert.match(
        requestSummary(
          { ...request, result, action, execution_result: 'done' },
          300,
        ),
        new RegExp(
          `was ${result}, but the MX later confirmed ${action === 'release' ? 'release' : 'discard'}`,
        ),
      );
  assert.match(
    requestSummary(
      { ...request, result: 'done', execution_result: 'done' },
      300,
    ),
    /not a delivery receipt/,
  );
  assert.match(
    requestSummary({ ...request, execution_result: 'expired' }, 300),
    /without applying it/,
  );
  assert.match(
    requestSummary({ ...request, execution_result: 'conflict' }, 300),
    /did not apply/,
  );
  assert.match(
    requestSummary({ ...request, execution_result: 'unexpected' }, 300),
    /unrecognized MX receipt/,
  );
});
test('a done receipt with an older held snapshot cannot enable another action', () => {
  assert.equal(receiptAwaitingState(null), false);
  assert.equal(
    receiptAwaitingState({ status: 'quarantined', requests: [request] }),
    false,
  );
  assert.equal(
    receiptAwaitingState({
      status: 'quarantined',
      requests: [{ ...request, execution_result: 'done' }],
    }),
    true,
  );
  assert.equal(
    receiptAwaitingState({
      status: 'pending',
      requests: [{ ...request, execution_result: 'done' }],
    }),
    false,
  );
});
