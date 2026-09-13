import assert from 'node:assert/strict';
import test from 'node:test';
import {
  authenticationResult,
  contribution,
  decisionExplanation,
  deliveryStatus,
  duration,
  evidenceState,
  nextRetry,
  mergeDiagnosticRecipient,
  policySummary,
  recipientHistory,
  smtpOutcome,
  smtpPhase,
  smtpReply,
  timestamp,
  transcriptNotice,
  weightEffect,
} from '../app/diagnostics-formatters.ts';
import { deliverySummary } from '../app/presentation.ts';

test('SMTP acceptance is not represented as an inbox delivery guarantee', () => {
  assert.equal(
    deliveryStatus('delivered'),
    "Accepted by destination",
  );
  assert.equal(smtpOutcome('delivered'), "Accepted by destination");
  assert.equal(smtpOutcome('temporary'), "Temporary failure");
  assert.equal(smtpOutcome('permanent'), "Permanent rejection");
  assert.equal(deliveryStatus('sending'), "Delivery in progress");
  assert.match(deliveryStatus('unexpected'), /Unknown state/);
  assert.match(smtpOutcome('unexpected'), /Unknown outcome/);
});

test('only pending recipients show a retry date, including an overdue retry', () => {
  const next = 1_800_000_000;
  assert.match(
    nextRetry('pending', next, (next - 1) * 1000),
    /Next retry scheduled/,
  );
  assert.match(nextRetry('pending', next, next * 1000), /due since/);
  assert.match(nextRetry('pending', 0), /date not recorded/);
  assert.match(nextRetry('pending', Number.NaN), /date not recorded/);
  assert.match(nextRetry('pending', Number.MAX_VALUE), /date not recorded/);
  assert.match(nextRetry('sending', next), /Attempt in progress/);
  for (const status of [
    'delivered',
    'failed',
    'notified',
    'quarantined',
    'discarded',
    'expired',
  ]) {
    assert.match(
      nextRetry(status, next),
      /No retry scheduled/,
    );
  }
});

test('SMTP phases distinguish command acceptance from transfer completion', () => {
  for (const [phase, label] of [
    ['dns', 'DNS'],
    ['connect', 'TCP'],
    ['ehlo', 'EHLO'],
    ['starttls', 'STARTTLS'],
    ['tls', "verification"],
    ['tls_verified', "certificate verified"],
    ['ehlo_tls', "after TLS"],
    ['mail_from', 'MAIL FROM'],
    ['rcpt_to', 'RCPT TO'],
    ['data', 'transfer start'],
    ['data_result', "Final response"],
    ['final', "Final response"],
    ['quit', 'QUIT'],
  ])
    assert.ok(smtpPhase(phase).includes(label), phase);
  assert.equal(smtpPhase('future_phase'), "Phase future_phase");
  assert.equal(smtpReply(250, '2.0.0'), "250 · command accepted · 2.0.0");
  assert.match(smtpReply(354, null), /continue exchange/);
  assert.match(smtpReply(451, '4.7.1'), /temporary failure · 4.7.1/);
  assert.match(smtpReply(550, '5.1.1'), /permanent rejection · 5.1.1/);
  assert.equal(smtpReply(null, null), "SMTP code not recorded");
});

test('missing historic transcripts never invent successful SMTP steps', () => {
  assert.match(
    transcriptNotice(0),
    /No historical SMTP transcript recorded/,
  );
  assert.match(transcriptNotice(0), /do not establish/);
  assert.equal(transcriptNotice(1), "1 recorded SMTP log.");
  assert.equal(transcriptNotice(2), "2 recorded SMTP logs.");
  assert.equal(
    transcriptNotice(50, 50, false),
    "50 recorded SMTP logs.",
  );
  assert.equal(timestamp(0), "Date not recorded");
  assert.equal(timestamp(Number.MAX_VALUE), "Date not recorded");
  assert.equal(duration(null), "Duration not recorded");
  assert.equal(duration(-1), "Duration not recorded");
  assert.equal(duration(0), '0 ms');
  assert.equal(duration(1250), '1.25 s');
});

test('global log budget omissions are distinct from missing historical transcripts', () => {
  for (const [loaded, available, truncated] of [
    [0, 12, true],
    [5, 20, true],
    [50, 120, true],
    [0, 0, true],
    [0, 12, false],
  ]) {
    const notice = transcriptNotice(loaded, available, truncated);
    assert.match(notice, /Partial history/);
    assert.doesNotMatch(notice, /No historical SMTP transcript/);
    assert.ok(notice.includes(`of ${available} available`));
  }
  assert.match(
    transcriptNotice(0, 0, false),
    /No historical SMTP transcript recorded/,
  );
  assert.equal(
    transcriptNotice(12, 12, false),
    "12 recorded SMTP logs.",
  );
});

test('scoped delivery completion updates state and badges while preserving other recipients and quarantine metadata', () => {
  const logs = [{ id: 22, attempt: 2 }];
  const response = {
    message_id: 'message-a',
    analysis: { elapsed_ms: 10 },
    recipients: [
      {
        delivery_id: 123,
        address: 'alice@example.test',
        status: 'delivered',
        destination: 'alice@upstream.test',
        attempts: 2,
        next_attempt: 0,
        last_error: null,
        logs,
        logs_available: 80,
        logs_truncated: true,
      },
    ],
  };
  const previous = [
    {
      delivery_id: 123,
      address: 'alice@example.test',
      status: 'pending',
      attempts: 1,
      next_attempt: 1800000000,
      last_error: '451 retry later',
      held_until: 100,
      released_at: 90,
    },
    {
      delivery_id: 456,
      address: 'bob@example.test',
      status: 'delivered',
      held_until: 200,
      released_at: 190,
    },
  ];
  const updated = recipientHistory(response, 'message-a', 123);
  assert.equal(updated, response.recipients[0]);
  const merged = mergeDiagnosticRecipient(previous, updated);
  assert.equal(merged.length, 2);
  assert.equal(merged[0].status, 'delivered');
  assert.equal(merged[0].attempts, 2);
  assert.equal(merged[0].next_attempt, 0);
  assert.equal(merged[0].last_error, null);
  assert.equal(merged[0].held_until, 100);
  assert.equal(merged[0].released_at, 90);
  assert.equal(merged[1], previous[1]);
  assert.equal(previous[0].status, 'pending');
  assert.equal(deliverySummary(merged).label, "Accepted by destination");
  assert.match(
    nextRetry(updated.status, updated.next_attempt),
    /No retry/,
  );
  assert.equal(response.analysis.elapsed_ms, 10);
});

test('scoped merges match delivery id and compose without losing another recipient update', () => {
  const previous = [
    { delivery_id: 1, address: 'same@example.test', status: 'pending' },
    {
      delivery_id: 2,
      address: 'same@example.test',
      status: 'pending',
      held_until: 20,
    },
  ];
  const first = mergeDiagnosticRecipient(previous, {
    delivery_id: 1,
    status: 'delivered',
  });
  const second = mergeDiagnosticRecipient(first, {
    delivery_id: 2,
    status: 'failed',
  });
  assert.equal(second[0].status, 'delivered');
  assert.equal(second[1].status, 'failed');
  assert.equal(second[1].held_until, 20);
  assert.deepEqual(
    mergeDiagnosticRecipient(second, { delivery_id: 3, status: 'delivered' }),
    second,
  );
});

test('a scoped response arriving after global refresh cancellation cannot replace newer state', async () => {
  const controller = new AbortController();
  const newer = [{ delivery_id: 123, status: 'delivered' }];
  let resolve;
  const pending = new Promise((done) => {
    resolve = done;
  });
  const applying = pending.then((data) => {
    const updated = recipientHistory(data, 'message-a', 123, controller.signal);
    return updated ? mergeDiagnosticRecipient(newer, updated) : newer;
  });
  controller.abort();
  resolve({
    message_id: 'message-a',
    recipients: [{ delivery_id: 123, status: 'pending' }],
  });
  assert.equal(await applying, newer);
});

test('scoped history rejects a stale message, another recipient, missing access or a full-list response', () => {
  const recipient = {
    delivery_id: 123,
    logs: [],
    logs_available: 0,
    logs_truncated: false,
  };
  const response = { message_id: 'message-a', recipients: [recipient] };
  for (const [data, messageId, deliveryId] of [
    [response, 'message-b', 123],
    [response, 'message-a', 456],
    [{ ...response, recipients: [] }, 'message-a', 123],
    [
      {
        ...response,
        recipients: [recipient, { ...recipient, delivery_id: 456 }],
      },
      'message-a',
      123,
    ],
  ])
    assert.throws(
      () => recipientHistory(data, messageId, deliveryId),
      /does not match the selected recipient/,
    );
});

test('positive, negative and zero weights retain their meaning without percent formatting', () => {
  assert.equal(contribution(1.25), '+1.25');
  assert.equal(contribution(-1.25), '−1.25');
  assert.equal(contribution(-0), '0');
  assert.equal(contribution(0.00001), '+1.00e-5');
  assert.equal(contribution(null), "Not recorded");
  assert.equal(contribution(Number.NaN), "Not recorded");
  assert.match(weightEffect(0.2), /Increases/);
  assert.match(weightEffect(-0.2), /Reduces/);
  assert.match(weightEffect(0), /Advisory signal · no numerical effect/);
  assert.match(weightEffect(Number.NaN), /not recorded/);
  assert.match(
    decisionExplanation('fusion'),
    /do not determine the final fusion estimate/,
  );
  assert.match(
    decisionExplanation('antivirus'),
    /takes priority over content weights and fusion/,
  );
  assert.match(decisionExplanation(), /Decision source not recorded/);
});

test('historical policy is explicit and never reconstructed from current defaults', () => {
  assert.match(policySummary(null), /Historical threshold and mode not recorded/);
  assert.match(policySummary(null), /Current settings are not used/);
  assert.doesNotMatch(policySummary(null), /95/);
  const policy = {
    version: 'policy-1',
    threshold: 87.5,
    mode: 'observe',
    require_corroboration: true,
    rule_weights: {},
  };
  assert.equal(
    policySummary(policy),
    "Observation · Recorded content threshold 87.5 / 100 · corroboration required",
  );
  assert.match(policySummary({ ...policy, mode: 'tag' }), /^Tagging/);
  assert.match(
    policySummary({ ...policy, mode: 'enforce', require_corroboration: false }),
    /^Actions enabled .*corroboration not required$/,
  );
});

test('authentication honors Rust snake_case outcomes and distinguishes absence from success', () => {
  assert.equal(authenticationResult('pass'), "Pass");
  assert.equal(authenticationResult('soft_fail'), "Soft fail (softfail)");
  assert.equal(authenticationResult('temp_error'), "Temporary error");
  assert.equal(authenticationResult('perm_error'), "Permanent error");
  assert.equal(authenticationResult(null), "Result not recorded");
  assert.equal(authenticationResult('unknown'), "Result not recorded");
  assert.match(authenticationResult('none'), /No authentication result/);
  for (const state of [
    'disabled',
    'not_run',
    'unavailable',
    'busy',
    'skipped',
    'limited',
  ]) {
    assert.notEqual(evidenceState(state), evidenceState('complete'));
  }
  assert.equal(evidenceState(undefined), "State not recorded");
});

test('suppressed bounces are explicitly distinguished from sent failure notices', () => {
  assert.equal(deliveryStatus('dsn_suppressed'), "Notification suppressed · backscatter protection");
  assert.equal(deliveryStatus('notified'), "Failure notification handled");
  assert.match(nextRetry('dsn_suppressed', 1), /No retry/);
});
