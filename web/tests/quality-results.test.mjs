import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import ts from 'typescript';
const source=await readFile(new URL('../app/quality-results.tsx',import.meta.url),'utf8');
const js=ts.transpileModule(source,{compilerOptions:{jsx:ts.JsxEmit.ReactJSX,module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2022}}).outputText.replace(/from (["'])([^"']+)\1/g,(_,q,name)=>`from ${JSON.stringify(import.meta.resolve(name))}`);
const {FullSampleResults,PolicyResults,TrainingResults,ExposureNotice,QualificationStatus}=await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`);
const render=(component,props)=>renderToStaticMarkup(createElement(component,props));
const metrics={messages:2,tp:1,fp:0,review:0,recall:1,fpr:0,precision:1,fpr_ci95:[0,.5],recall_ci95:[.5,1]};

test('new engine comparisons explain partial verdicts without claiming independent qualification',()=>{
  const html=render(FullSampleResults,{report:{baseline:metrics,evaluation_scope:'recorded_engines_with_separate_policy_results'}});
  assert.match(html,/Incomplete coverage does not erase an explicit verdict/);
  assert.match(html,/Recipient overrides are reported separately/);
  assert.doesNotMatch(html,/Historical mixed policy/);
});
test('old reports retain an explicit mixed-baseline explanation',()=>{
  const html=render(FullSampleResults,{report:{baseline:metrics}});
  assert.match(html,/Historical mixed policy baseline/);
  assert.match(html,/cannot establish engine-only accuracy/);
});
test('missing action history is not shown as zero errors or successful delivery',()=>{
  const html=render(PolicyResults,{});
  assert.match(html,/were not recorded/);
  assert.doesNotMatch(html,/<table|0\.00%/);
});
test('recorded requested and effective actions remain separate from classification',()=>{
  const html=render(PolicyResults,{value:{classification:metrics,records:2,snapshots:1,legacy_without_snapshot:1,invalid_snapshots:0,
    requested_actions:{legitimate:{tag:1},spam:{not_recorded:1}},effective_actions:{legitimate:{deliver:1},spam:{not_recorded:1}},action_transitions:[{requested:'tag',effective:'deliver',records:1}]}});
  assert.match(html,/Recipient policy/);
  assert.match(html,/Requested/);
  assert.match(html,/Effective/);
  assert.match(html,/not delivery confirmations/);
  assert.match(html,/does not prove downstream delivery/);
  assert.match(html,/1 legacy records/);
  assert.doesNotMatch(html,/<th>Engine<\/th>/);
});

test('candidate evaluations also declare engine-only scope',()=>{
  const html=render(FullSampleResults,{report:{baseline:metrics,candidate:metrics,evaluation_scope:'shadow_engine_with_antivirus_guard_not_recipient_policy_replay'}});
  assert.match(html,/Full-sample engine results and coverage/);
  assert.match(html,/Candidate/);
  assert.doesNotMatch(html,/Historical mixed policy baseline/);
});

test('training metrics come from the candidate test fold, not baseline counters',()=>{
  const html=render(TrainingResults,{risk:{test:metrics}});
  assert.match(html,/Development sample · candidate test fold/);
  assert.match(html,/not a prospective independent evaluation/);
  assert.match(html,/Candidate/);
  assert.doesNotMatch(html,/NoiseFence/);
});
test('unprepared training candidates do not invent results',()=>{
  const html=render(TrainingResults,{});
  assert.match(html,/No candidate test-fold metrics/);
  assert.doesNotMatch(html,/<table/);
});

const exposure={schema:'noisefence-quality-exposure-1',tracked:true,candidate_bound:true,observation_window_covered:true,not_previously_exposed:true,eligible_for_independence_checks:true};
const acceptance={passes_pilot:true,meets_final_confidence_bounds:true};
test('unused exports retain separate independent qualification requirements',()=>{
  const html=render(ExposureNotice,{value:exposure});
  assert.match(html,/At export time/);
  assert.match(html,/still require validation/);
});
test('reused or untracked reports never claim current pilot qualification',()=>{
  for(const value of [undefined,{...exposure,candidate_bound:false},{...exposure,schema:'future'},{...exposure,tracked:false},{...exposure,not_previously_exposed:false},{...exposure,observation_window_covered:false}]){
    const html=render(QualificationStatus,{acceptance,exposure:value});
    assert.match(html,/Qualification unavailable/);
    assert.doesNotMatch(html,/criteria met|bounds: met/);
  }
  assert.match(render(ExposureNotice,{value:{...exposure,not_previously_exposed:false}}),/already exposed/);
});
