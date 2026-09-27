import test from 'node:test';
import assert from 'node:assert/strict';
import {classification, scorePresentation, arbitrationExplanation} from '../app/presentation.ts';
import {policySummary} from '../app/diagnostics-formatters.ts';
const make = (score, complete = true, category = 'spam') => ({
  score, complete, category, decision: {source: 'legacy', outcome: score === null ? 'legitimate' : 'unwanted', score},
  assessment: {version:1, category, complete, score:{value:score, model:'fixture'}, classification_source:'score_threshold', score_resolution:{threshold:95, score, partial:!complete, projected:false, decision:{outcome:score === null ? 'legitimate' : 'unwanted'}}},
});
test('resolved disagreements display their score, threshold and separate incomplete coverage',()=>{
  for (const complete of [true,false]) {
    const m = make(99.8, complete);
    assert.equal(classification(m).label,'Spam');
    const shown=scorePresentation(m);
    assert.equal(shown.value,99.8);
    assert.match(shown.detail,/threshold 95.00/);
    assert.doesNotMatch(shown.detail,/decision is undetermined|engine abstains/);
    assert.equal(shown.kind,complete?'content':'partial');
    const original={baseline:{outcome:'unwanted'},opinion:'legitimate',resolution:'disagreement',decision:{outcome:'undetermined'}};
    assert.match(arbitrationExplanation(original,m.assessment.score_resolution).detail,/Automatic threshold policy: Spam/);
  }
});
test('missing scores do not invent zero or mask recipient rules and malware',()=>{
  const m=make(null,false,'legitimate');
  assert.equal(classification(m).label,'Ham');
  assert.equal(scorePresentation(m).value,null);
  m.assessment.category='spam';m.assessment.classification_source='recipient_policy';
  assert.equal(classification(m).label,'Spam');
  assert.match(scorePresentation(m).detail,/Recipient rules determine/);
  m.decision.source='antivirus';
  assert.equal(classification(m).label,'Spam');
});
test('historical projections and recorded automatic settings are explained',()=>{
  const m=make(99.8);m.assessment.score_resolution.projected=true;
  assert.match(scorePresentation(m).detail,/original decision and delivery are preserved/);
  assert.match(policySummary({mode:'observe',threshold:95,require_corroboration:true,resolve_uncertain_by_score:true}),/uncertain results resolved by score/);
});
