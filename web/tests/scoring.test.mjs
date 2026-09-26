import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import ts from 'typescript';
import { scoreAdjustment, scoreValue } from '../app/scoring-format.ts';

const source = await readFile(new URL('../app/scoring-view.tsx',import.meta.url),'utf8');
const js=ts.transpileModule(source,{compilerOptions:{jsx:ts.JsxEmit.ReactJSX,module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2022}}).outputText
  .replaceAll('"react/jsx-runtime"',JSON.stringify(import.meta.resolve('react/jsx-runtime')))
  .replaceAll("'./scoring-format'",JSON.stringify(new URL('../app/scoring-format.ts',import.meta.url).href));
const {ScoreAccounting,FusionAccountingView}=await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`);
const report={version:'content-logit-deduplicated-1',baseline:-5,lexical:null,semantic:null,rules_total:1.5,total_logit:-3.5,score:2.9312,invalid_inputs:0,
  contributions:[{id:'llm_advisory',family:'llm',occurrences:2,proposed:1.5,retained:1.5,adjustment:'duplicate'}]};

test('actual accounting view distinguishes retained inputs from duplicate occurrences',()=>{
  const html=renderToStaticMarkup(createElement(ScoreAccounting,{report}));
  assert.match(html,/Repeated signal counted once/);
  assert.match(html,/Fixed rules baseline/);
  assert.match(html,/not probabilities/);
  assert.match(html,/not an independent confirmation/);
  assert.match(html,/2.9312/);
  assert.match(html,/Distinct correlated signals still need joint calibration/);
});

test('missing legacy accounting and an invalid index never display a fabricated zero',()=>{
  const legacy=renderToStaticMarkup(createElement(ScoreAccounting,{}));
  assert.match(legacy,/not recorded/);
  assert.doesNotMatch(legacy,/0–100|Applied once/);
  const html=renderToStaticMarkup(createElement(ScoreAccounting,{report:{...report,score:null,total_logit:null}}));
  assert.match(html,/No usable content index/);
  assert.match(html,/not interpreted as zero risk/);
  assert.equal(scoreValue(NaN),'Not available');
  assert.equal(scoreValue(null),'Not available');
  assert.equal(scoreValue(0),'0');
  assert.match(scoreAdjustment('detector_policy'),/usable detector opinion/);
});


test('capped fusion view shows raw and retained units without implying activation',()=>{
  const html=renderToStaticMarkup(createElement(FusionAccountingView,{report:{version:'noisefence-fusion-family-caps-1',policy_sha256:'a'.repeat(64),bias:-2,total_logit:1,
    families:{llm:{raw:8,retained:3,minimum:-1,maximum:3}}}}));
  assert.match(html,/8<\/td><td>3 · capped/);
  assert.match(html,/learned log-odds/);
  assert.match(html,/before calibration/);
  assert.match(html,/Observation mode does not change delivery/);
  assert.match(html,/requires refitting/);
  assert.match(html,/role of this calculation.*not recorded/);
  const comparison=renderToStaticMarkup(createElement(FusionAccountingView,{decisionSource:'legacy',report:{version:'fixture',families:{},bias:0,total_logit:0}}));
  assert.match(comparison,/did not supply the final detector decision/);
  assert.equal(renderToStaticMarkup(createElement(FusionAccountingView,{})),'');
});


test('dependency accounting shows excluded facts without reusing their proposed weights', () => {
  const html = renderToStaticMarkup(createElement(ScoreAccounting, {report: {
    ...report, version: 'content-evidence-combination-2', rules_total: 2,
    contributions: [
      {id:'spf_fail',family:'authentication',occurrences:1,proposed:1,retained:0,adjustment:'subsumed_evidence',subsumed_by:'dmarc_fail'},
      {id:'smtp_policy_contribution',family:'smtp',occurrences:1,proposed:1.5,retained:0,adjustment:'unavailable_evidence'},
    ],
  }}));
  assert.match(html, /Already included in the composite finding/);
  assert.match(html, /<code>dmarc_fail<\/code>/);
  assert.match(html, /Excluded — no usable supporting result/);
  const escaped = renderToStaticMarkup(createElement(ScoreAccounting, {report: {...report,
    contributions:[{...report.contributions[0],subsumed_by:'<script>private</script>'}],
  }}));
  assert.doesNotMatch(escaped, /<script>/);
  assert.match(escaped, /&lt;script&gt;/);
});
