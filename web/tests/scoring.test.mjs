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
const {ScoreAccounting}=await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`);
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
