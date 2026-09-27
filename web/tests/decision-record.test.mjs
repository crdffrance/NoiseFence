import assert from 'node:assert/strict';
import test from 'node:test';
import { classification, scorePresentation } from '../app/presentation.ts';
import { coveragePresentation, receiptAssessment } from '../app/assessment.ts';

const assessment = {
  version: 1, category: 'spam', complete: false,
  score: {value: 99, raw: 99, decision: 99, kind: 'partial', source: 'decision', model: 'fixture', scale: 100},
  decision: {source: 'legacy', outcome: 'unwanted', score: 99, model: 'fixture'},
  score_resolution: null, decision_recorded: true, incomplete_reasons: ['smtp_policy_unavailable'], supplementary_gaps: [],
  content_threshold: 95, mode: 'observe', policy_version: 'fixture', classification_source: 'recorded_decision',
  action: {requested: 'quarantine', effective: 'deliver', reason: 'observation', quarantine_days: 14}, subject_tag: 'none',
};
const record = {
  version: 1, recorded_at: 1234, policy_sha256: 'a'.repeat(64), profile: null, rule_ids: [],
  classification: 'spam', coverage: 'partial', assessment,
};
const mail = {
  category: 'legitimate', complete: true, score: 0, tagged: false, pub_tagged: false,
  recipient_decision: record,
};

test('receipt classification, risk and coverage take precedence over live or legacy display fields', () => {
  assert.equal(classification(mail, 100).label, 'Spam');
  assert.equal(classification(mail, 0).label, 'Spam');
  assert.equal(scorePresentation(mail).value, 99);
  assert.equal(scorePresentation(mail).kind, 'partial');
  assert.equal(coveragePresentation(mail).label, 'Partial analysis');
  assert.match(coveragePresentation(mail).detail, /SMTP \/ DNS/);
  assert.equal(receiptAssessment(mail).action.effective, 'deliver');
  assert.equal(scorePresentation({...mail, assessment: {...assessment, score: {...assessment.score, value: 0}}}).value, 99);
});

test('unmeasured fail-open and malware preserve unavailable risk under three-way badges', () => {
  const empty = {...assessment, category: 'undetermined', score: {...assessment.score, value: null, raw: null, decision: null, kind: 'unavailable'}};
  for (const [finding, label] of [['unassessed', 'Ham'], ['malware', 'Spam']]) {
    const unavailable = {...mail, recipient_decision: {...record, classification: finding, coverage: 'unavailable', assessment: empty}};
    assert.equal(classification(unavailable).label, label);
    assert.equal(scorePresentation(unavailable).value, null);
    assert.equal(coveragePresentation(unavailable).label, 'Content analysis unavailable');
  }
});

test('marketing policy keeps its low threat index and explicit delivery action', () => {
  const publicity = {...mail, recipient_decision: {...record, classification: 'publicity', coverage: 'complete', assessment: {...assessment, category: 'publicity', complete: true, score: {...assessment.score, value: 12, kind: 'content'}}}};
  assert.equal(classification(publicity).label, 'Pub');
  assert.equal(scorePresentation(publicity).value, 12);
  assert.equal(receiptAssessment(publicity).action.requested, 'quarantine');
});

for (const version of [1, 2]) {
  test(`receipt schema ${version} preserves detailed classification, score and unavailable coverage`, () => {
    const snapshot = {...mail, recipient_decision: {...record, version, classification: 'phishing',
      coverage: 'unavailable', activation_epoch: version === 2 ? {sequence: 7, revision: 12, digest: 'a'.repeat(64)} : undefined}};
    assert.equal(classification(snapshot, 100).label, 'Spam');
    assert.equal(scorePresentation(snapshot).value, 99);
    assert.equal(coveragePresentation(snapshot).label, 'Content analysis unavailable');
    assert.equal(receiptAssessment(snapshot).action.effective, 'deliver');
  });
}
