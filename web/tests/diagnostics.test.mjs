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
    'Accepté par le serveur destinataire',
  );
  assert.equal(smtpOutcome('delivered'), 'Accepté par le serveur destinataire');
  assert.equal(smtpOutcome('temporary'), 'Échec temporaire');
  assert.equal(smtpOutcome('permanent'), 'Refus permanent');
  assert.equal(deliveryStatus('sending'), 'Transmission en cours');
  assert.match(deliveryStatus('unexpected'), /État inconnu/);
  assert.match(smtpOutcome('unexpected'), /Résultat inconnu/);
});

test('only pending recipients show a retry date, including an overdue retry', () => {
  const next = 1_800_000_000;
  assert.match(
    nextRetry('pending', next, (next - 1) * 1000),
    /Prochaine tentative prévue/,
  );
  assert.match(nextRetry('pending', next, next * 1000), /attendue depuis/);
  assert.match(nextRetry('pending', 0), /date non enregistrée/);
  assert.match(nextRetry('pending', Number.NaN), /date non enregistrée/);
  assert.match(nextRetry('pending', Number.MAX_VALUE), /date non enregistrée/);
  assert.match(nextRetry('sending', next), /Tentative en cours/);
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
      /Aucune nouvelle tentative planifiée/,
    );
  }
});

test('SMTP phases distinguish command acceptance from transfer completion', () => {
  for (const [phase, label] of [
    ['dns', 'DNS'],
    ['connect', 'TCP'],
    ['ehlo', 'EHLO'],
    ['starttls', 'STARTTLS'],
    ['tls', 'vérification'],
    ['tls_verified', 'certificat vérifié'],
    ['ehlo_tls', 'après TLS'],
    ['mail_from', 'MAIL FROM'],
    ['rcpt_to', 'RCPT TO'],
    ['data', 'ouverture'],
    ['data_result', 'Réponse finale'],
    ['final', 'Réponse finale'],
    ['quit', 'QUIT'],
  ])
    assert.ok(smtpPhase(phase).includes(label), phase);
  assert.equal(smtpPhase('future_phase'), 'Étape future_phase');
  assert.equal(smtpReply(250, '2.0.0'), '250 · commande acceptée · 2.0.0');
  assert.match(smtpReply(354, null), /poursuite de l’échange/);
  assert.match(smtpReply(451, '4.7.1'), /échec temporaire · 4.7.1/);
  assert.match(smtpReply(550, '5.1.1'), /refus permanent · 5.1.1/);
  assert.equal(smtpReply(null, null), 'Sans code SMTP enregistré');
});

test('missing historic transcripts never invent successful SMTP steps', () => {
  assert.match(
    transcriptNotice(0),
    /Aucune transcription SMTP historique enregistrée/,
  );
  assert.match(transcriptNotice(0), /ne permet pas de déduire/);
  assert.equal(transcriptNotice(1), '1 journal SMTP enregistré.');
  assert.equal(transcriptNotice(2), '2 journaux SMTP enregistrés.');
  assert.equal(
    transcriptNotice(50, 50, false),
    '50 journaux SMTP enregistrés.',
  );
  assert.equal(timestamp(0), 'Date non enregistrée');
  assert.equal(timestamp(Number.MAX_VALUE), 'Date non enregistrée');
  assert.equal(duration(null), 'Durée non enregistrée');
  assert.equal(duration(-1), 'Durée non enregistrée');
  assert.equal(duration(0), '0 ms');
  assert.equal(duration(1250), '1,25 s');
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
    assert.match(notice, /Historique partiel/);
    assert.doesNotMatch(notice, /Aucune transcription SMTP historique/);
    assert.ok(notice.includes(`sur ${available} disponible(s)`));
  }
  assert.match(
    transcriptNotice(0, 0, false),
    /Aucune transcription SMTP historique enregistrée/,
  );
  assert.equal(
    transcriptNotice(12, 12, false),
    '12 journaux SMTP enregistrés.',
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
  assert.equal(deliverySummary(merged).label, 'Accepté par le serveur');
  assert.match(
    nextRetry(updated.status, updated.next_attempt),
    /Aucune nouvelle tentative/,
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
      /ne correspond pas au destinataire sélectionné/,
    );
});

test('positive, negative and zero weights retain their meaning without percent formatting', () => {
  assert.equal(contribution(1.25), '+1,25');
  assert.equal(contribution(-1.25), '−1,25');
  assert.equal(contribution(-0), '0');
  assert.equal(contribution(0.00001), '+1,00e-5');
  assert.equal(contribution(null), 'Non enregistrée');
  assert.equal(contribution(Number.NaN), 'Non enregistrée');
  assert.match(weightEffect(0.2), /Augmente/);
  assert.match(weightEffect(-0.2), /Réduit/);
  assert.match(weightEffect(0), /consultatif · aucun effet numérique/);
  assert.match(weightEffect(Number.NaN), /non enregistré/);
  assert.match(
    decisionExplanation('fusion'),
    /ne déterminent pas le score final/,
  );
  assert.match(
    decisionExplanation('antivirus'),
    /prime sur les poids historiques et la fusion/,
  );
  assert.match(decisionExplanation(), /Source de décision non enregistrée/);
});

test('historical policy is explicit and never reconstructed from current defaults', () => {
  assert.match(policySummary(null), /seuil et mode à la réception inconnus/);
  assert.match(policySummary(null), /réglages actuels ne sont pas utilisés/);
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
    'Observation · seuil historique 87,5 / 100 · confirmation requise',
  );
  assert.match(policySummary({ ...policy, mode: 'tag' }), /^Marquage/);
  assert.match(
    policySummary({ ...policy, mode: 'enforce', require_corroboration: false }),
    /^Application des actions .*confirmation non requise$/,
  );
});

test('authentication honors Rust snake_case outcomes and distinguishes absence from success', () => {
  assert.equal(authenticationResult('pass'), 'Réussi (pass)');
  assert.equal(authenticationResult('soft_fail'), 'Échec souple (softfail)');
  assert.equal(authenticationResult('temp_error'), 'Erreur temporaire');
  assert.equal(authenticationResult('perm_error'), 'Erreur permanente');
  assert.equal(authenticationResult(null), 'Résultat non enregistré');
  assert.equal(authenticationResult('unknown'), 'Résultat non enregistré');
  assert.match(authenticationResult('none'), /Aucun résultat/);
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
  assert.equal(evidenceState(undefined), 'État non enregistré');
});
