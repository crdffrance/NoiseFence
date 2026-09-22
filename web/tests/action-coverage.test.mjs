import assert from 'node:assert/strict';
import test from 'node:test';
import { actionBasis, actionReason, actionRequirement, coverageRequirements } from '../app/action-coverage.ts';

test('missing decision evidence, observation and rendering restrictions stay distinct', () => {
  assert.match(actionReason('observation'),/Observation mode/);
  assert.match(actionReason('action_requirements_unmet'),/evidence is missing/);
  assert.match(actionReason('subject_rewrite_unavailable'),/cannot be rewritten/);
  assert.equal(actionBasis('recipient_rule'),'Explicit recipient rule');
  assert.equal(actionBasis('score_threshold'),'Configured score threshold');
  assert.equal(actionRequirement('usable_score'),'Usable risk index');
});

test('the UI reads the recorded missing requirements without using current settings', () => {
  const recorded = {required:['usable_content','usable_score','threshold_met'],missing:['usable_content'],partial_actions:true};
  assert.deepEqual(coverageRequirements(recorded).map(r=>[r.id,r.met]),[
    ['usable_content',false],['usable_score',true],['threshold_met',true]
  ]);
  assert.equal(coverageRequirements({...recorded,missing:['subject_rewrite']}).at(-1).met,false);
});
