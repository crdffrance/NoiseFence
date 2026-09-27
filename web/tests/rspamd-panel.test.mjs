import assert from 'node:assert/strict';
import test from 'node:test';
import {readFile} from 'node:fs/promises';
import {createElement} from 'react';
import {renderToStaticMarkup} from 'react-dom/server';
import ts from 'typescript';
const source = await readFile(new URL('../app/rspamd-comparison.tsx', import.meta.url), 'utf8');
const code = ts.transpileModule(source, {compilerOptions: {jsx: ts.JsxEmit.ReactJSX, module: ts.ModuleKind.ESNext}}).outputText.replace(/from ["']([^"']+)["']/g, (_, name) => `from ${JSON.stringify(name.startsWith('./') ? new URL(`../app/${name.slice(2)}.ts`, import.meta.url).href : import.meta.resolve(name))}`);
const {RspamdComparison} = await import(`data:text/javascript;base64,${Buffer.from(code).toString('base64')}`);
const mail = {complete: true, score: 89.1, model: 'fixture', decision: {source: 'legacy', outcome: 'legitimate', score: 89.1}};
const base = {status: 'complete', comparison: 'inconclusive', score: 4.8, required_score: 15, action: 'greylist', symbols: [{name: 'TEST_SYMBOL', score: 4.8}], elapsed_ms: 717, profile: 'fixture', settings_sha256: 'a'.repeat(64), server: 'fixture', noisefence_outcome: 'legitimate'};

test('second-opinion panel explains deferral and preserves symbols without a manual decision task', () => {
  const html = renderToStaticMarkup(createElement(RspamdComparison, {mail, report: base, onRefresh: () => {}}));
  assert.match(html, /Rspamd — second opinion/);
  assert.match(html, /NoiseFence decides independently/);
  assert.match(html, /Rspamd proposes deferral/);
  assert.match(html, /proposal is not executed/);
  assert.match(html, /TEST_SYMBOL/);
  assert.doesNotMatch(html, /Needs review|No comparable verdict|review candidate/);
});
test('failed or disagreeing observer never asks the user to decide delivery', () => {
  for (const report of [{...base,status:'timeout',score:null}, {...base,action:'reject',comparison:'disagreement'}]) {
    const html = renderToStaticMarkup(createElement(RspamdComparison, {mail, report, onRefresh: () => {}}));
    assert.match(html, /never changes the NoiseFence verdict or delivery/);
    assert.doesNotMatch(html, /class="status review"|Needs review/);
  }
});
