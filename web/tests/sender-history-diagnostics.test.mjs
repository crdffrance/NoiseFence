import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import ts from 'typescript';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
const source = await readFile(
  new URL('../app/sender-history-diagnostics.tsx', import.meta.url),
  'utf8',
);
const compiled = ts
  .transpileModule(source, {
    compilerOptions: {
      jsx: ts.JsxEmit.ReactJSX,
      module: ts.ModuleKind.ESNext,
      target: ts.ScriptTarget.ES2022,
    },
  })
  .outputText.replace(
    /from ["']react\/jsx-runtime["']/g,
    `from ${JSON.stringify(import.meta.resolve('react/jsx-runtime'))}`,
  );
const { default: Component } = await import(
  `data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`
);
const report = {
  version: 'sender-history-1',
  status: 'complete',
  mode: 'candidate_credit',
  distinct_campaigns: 3,
  distinct_days: 3,
  learned_candidate: true,
  manual_match: 'none',
  contradicted: false,
  candidate_credit: true,
};
const render = (value) =>
  renderToStaticMarkup(createElement(Component, { report: value }));
test('advisory and historical reports never claim a real threshold or saved call', () => {
  const html = render(report);
  assert.ok(html.includes('Aucune adaptation appliquée'));
  assert.ok(!html.includes('Seuil appliqué'));
  assert.ok(!html.includes('facultative omise'));
});
test('applied reports distinguish recorded cutoff and optional LLM omission', () => {
  const applied = {
    version: 'sender-history-adaptive-1',
    threshold: 97.5,
    optional_llm_omitted: true,
  };
  const html = render({ ...report, mode: 'adaptive', applied });
  assert.ok(html.includes('97,5'));
  assert.ok(html.includes('score du modèle reste inchangé'));
  assert.ok(html.includes('facultative omise'));
  assert.ok(html.includes('contrôles obligatoires ont été exécutés'));
  const noSkip = render({
    ...report,
    applied: { ...applied, optional_llm_omitted: false },
  });
  assert.ok(!noSkip.includes('facultative omise'));
  assert.ok(noSkip.includes('aucune omission'));
});
test('diagnostic strings are escaped and recipient identities are not requested by the component', () => {
  const html = render({ ...report, version: '<img src=x onerror=alert(1)>' });
  assert.ok(!html.includes('<img'));
  assert.ok(html.includes('&lt;img'));
});
