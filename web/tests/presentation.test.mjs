import assert from 'node:assert/strict';
import test from 'node:test';
import {
  classification,
  deliverySummary,
  matchesAccount,
  checkFailure,
  publicitySignal,
} from '../app/presentation.ts';

test('failure diagnostics use fixed descriptions and do not echo untrusted text', () => {
  assert.match(checkFailure('timeout'), /Deadline/);
  assert.match(checkFailure('authentication'), /authentication/);
  assert.equal(checkFailure(null), '');
  assert.equal(
    checkFailure('private@example.org <script>'),
    "Unknown cause",
  );
});

test('publicity evidence stays visible independently of a security decision', () => {
  assert.ok(publicitySignal({ status: 'complete', verdict: 'promotion' }));
  assert.ok(publicitySignal({ status: 'complete', verdict: 'newsletter' }));
  assert.equal(
    publicitySignal({ status: 'limited', verdict: 'promotion' }),
    false,
  );
  assert.equal(
    publicitySignal({ status: 'complete', verdict: 'transactional' }),
    false,
  );
  assert.ok(!publicitySignal(undefined));
});
const mail = {
  category: 'publicity',
  complete: true,
  score: 99,
  tagged: false,
  pub_tagged: false,
};
test('primary grouping preserves native decisions and ignores live thresholds', () => {
  assert.equal(
    classification(
      {
        ...mail,
        decision: { source: 'fusion', outcome: 'undetermined', score: null },
      },
      95,
    ).label,
    "Ham",
  );
  assert.equal(
    classification(
      {
        ...mail,
        decision: { source: 'fusion', outcome: 'legitimate', score: 2 },
      },
      95,
    ).label,
    "Pub",
  );
  assert.equal(classification(mail, 95).label, 'Ham');
});
test('malware keeps priority over PUB and incomplete analysis', () => {
  assert.equal(
    classification(
      {
        ...mail,
        complete: false,
        decision: { source: 'antivirus', outcome: 'unwanted', score: null },
      },
      95,
    ).label,
    'Spam',
  );
  assert.equal(
    classification({ ...mail, complete: false }, 95).label,
    "Ham",
  );
});
test('message details cannot classify historical mail with an invented threshold', () => {
  assert.equal(
    classification(mail).label,
    "Ham",
  );
  assert.equal(
    classification(mail, Number.NaN).label,
    "Ham",
  );
  assert.equal(
    classification({
      ...mail,
      decision: { source: 'legacy', outcome: 'unwanted', score: 99 },
    }).label,
    'Spam',
  );
  assert.equal(
    classification({
      ...mail,
      decision: { source: 'fusion', outcome: 'legitimate', score: 2 },
    }).label,
    "Pub",
  );
});
test('mixed deliveries never look fully delivered while a copy is held or failed', () => {
  assert.equal(
    deliverySummary([{ status: 'delivered' }, { status: 'quarantined' }]).label,
    "Quarantined",
  );
  assert.equal(
    deliverySummary([{ status: 'delivered' }, { status: 'failed' }]).label,
    "Delivery failed",
  );
  assert.equal(
    deliverySummary([{ status: 'delivered' }, { status: 'pending' }]).label,
    "In progress",
  );
  assert.equal(
    deliverySummary([{ status: 'delivered' }, { status: 'discarded' }]).label,
    "Mixed delivery states",
  );
  assert.equal(deliverySummary([]).label, "Not recorded");
  assert.equal(
    deliverySummary([{ status: 'delivered' }]).label,
    "Accepted by destination",
  );
});
test('account search combines access scope and role without dropping disabled accounts', () => {
  const account = {
    username: 'Alice',
    addresses: ['*@atelier.test'],
    admin: false,
    disabled: true,
  };
  assert.equal(matchesAccount(account, ' ATELIER ', 'user'), true);
  assert.equal(matchesAccount(account, 'alice', 'disabled'), true);
  assert.equal(matchesAccount(account, '', 'admin'), false);
  assert.equal(matchesAccount(account, 'bob', 'all'), false);
});

test('recipient classification is visible without rewriting the detector decision', () => {
  const original = {
    ...mail,
    decision: { source: 'fusion', outcome: 'unwanted', score: 99 },
  };
  assert.equal(
    classification({ ...original, delivery_classification: 'publicity' }).label,
    "Pub",
  );
  assert.equal(
    classification({ ...original, delivery_classification: 'legitimate' })
      .label,
    "Ham",
  );
  assert.equal(original.decision.outcome, 'unwanted');
  assert.equal(
    classification({
      ...original,
      complete: false,
      delivery_classification: 'publicity',
    }).label,
    "Pub",
  );
  assert.equal(
    classification({
      ...original,
      decision: { source: 'antivirus', outcome: 'unwanted', score: null },
      delivery_classification: 'legitimate',
    }).label,
    'Spam',
  );
});

test('historical disagreements keep their diagnostics under a neutral Ham grouping', async () => {
  const { arbitrationExplanation } = await import('../app/presentation.ts');
  const report = {
    version: 'decision-policy-2',
    baseline: { outcome: 'unwanted', score: 99.99 },
    opinion: 'legitimate',
    resolution: 'disagreement',
    decision: { outcome: 'undetermined', score: null },
  };
  const text = arbitrationExplanation(report);
  assert.equal(text.title, "Opinions disagree");
  assert.match(text.detail, /Recorded baseline: Spam/);
  assert.match(text.detail, /Second opinion: Legitimate/);
  assert.match(text.detail, /The engine abstains/);
  assert.match(text.detail, /recipient rules/);
  assert.equal(
    classification({
      ...mail,
      decision: { source: 'legacy', ...report.decision },
    }).label,
    "Ham",
  );
  assert.equal(arbitrationExplanation(null), null);
});

test("a suppressed hostile-mail bounce never apps delivered", () => {
  assert.equal(deliverySummary([{status:'dsn_suppressed'}]).label, "Notification suppressed (backscatter protection)");
  assert.equal(deliverySummary([{status:'dsn_suppressed'},{status:'delivered'}]).label, "Delivery failed");
});

test('unassessed accepted receipts show a definitive delivery policy without claiming safety', () => {
  const mail = {recipient_decision: {
    version: 2,
    classification: 'unassessed',
    assessment: {version: 1, category: 'legitimate'},
  }};
  assert.deepEqual(classification(mail), {label: 'Ham', tone: 'neutral'});
});


test('all primary badges are three-way and detailed threats remain available', async () => {
  const {classificationDetail} = await import('../app/presentation.ts');
  for (const [detailed, category, expected] of [
    ['legitimate', 'legitimate', 'Ham'], ['publicity', 'publicity', 'Pub'],
    ['spam', 'spam', 'Spam'], ['phishing', 'spam', 'Spam'],
    ['malware', 'spam', 'Spam'], ['unassessed', 'legitimate', 'Ham'],
    ['unassessed', 'undetermined', 'Ham'],
  ]) {
    const item = {...mail, recipient_decision: {version: 2, classification: detailed,
      assessment: {version: 1, category}}};
    const before = JSON.stringify(item);
    assert.equal(classification(item).label, expected);
    if (['phishing','malware'].includes(detailed)) assert.match(classificationDetail(item), new RegExp(detailed));
    if (detailed === 'unassessed') assert.match(classificationDetail(item), /not a safety guarantee/);
    assert.equal(JSON.stringify(item), before);
  }
});


test('missing scores do not describe an explicit spam or pub rule as Ham', async () => {
  const {classificationDetail} = await import('../app/presentation.ts');
  for (const category of ['spam','publicity']) {
    const item = {...mail, assessment: {version:1, category, score_resolution:{score:null}}};
    assert.doesNotMatch(classificationDetail(item), /Ham/);
  }
});
