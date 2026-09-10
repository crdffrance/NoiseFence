import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import ts from 'typescript';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

// Compile the real component without starting a web server. Its only runtime
// imports are the JSX runtime and the pure diagnostic formatters.
const source = await readFile(new URL('../app/research-diagnostics.tsx', import.meta.url), 'utf8');
const compiled = ts.transpileModule(source, {
  compilerOptions: { jsx: ts.JsxEmit.ReactJSX, module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
}).outputText
  .replace(/from ["']react\/jsx-runtime["']/g, `from ${JSON.stringify(import.meta.resolve('react/jsx-runtime'))}`)
  .replace(/from ["']\.\/diagnostics-formatters["']/g, `from ${JSON.stringify(new URL('../app/diagnostics-formatters.ts', import.meta.url).href)}`);
const { default: ResearchDiagnostics } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`);
const render = (props) => renderToStaticMarkup(createElement(ResearchDiagnostics, props));

test('historical mail without optional research reports does not invent checks', () => {
  assert.equal(render({ analysis: {} }), '');
});

test('rendered heuristic details distinguish candidate weights and escape configured labels', () => {
  const html = render({ analysis: { heuristics: {
    status: 'limited', pattern_version: 'test-v1', settings_digest: 'hash',
    candidate_weight: 8, contribution: 0, limits_hit: ['body_limit'],
    findings: [{ id: 'test', label: '<img src=x onerror=alert(1)>', family: 'urgency', matches: 2, candidate_weight: 8 }],
  } } });
  assert.ok(html.includes('Contribution appliquée'));
  assert.ok(html.includes('Aucune contribution numérique sur cette analyse partielle'));
  assert.ok(html.includes('&lt;img'));
  assert.ok(!html.includes('<img'));
  assert.ok(html.includes('body_limit'));
});

test('dynamic analysis without findings is never rendered as a safety guarantee or an automatic release', () => {
  const html = render({ analysis: {}, sandboxResults: [{
    part: 1, state: 'complete', detail: null,
    result: { status: 'complete', outcome: 'no_findings', detail: null, findings: [], findings_truncated: false, engine_version: '2.5', isolation_verified: false },
  }] });
  assert.ok(html.includes('Partie 2'));
  assert.ok(html.includes('Aucune observation rapportée'));
  assert.ok(html.includes('ne libèrent pas automatiquement'));
  assert.ok(html.includes('ne garantit pas'));
  assert.ok(html.includes('validation indépendante'));
});
