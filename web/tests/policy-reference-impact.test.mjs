import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import ts from 'typescript';
const source = await readFile(
  new URL('../app/policy-reference-impact.tsx', import.meta.url),
  'utf8',
);
const js = ts
  .transpileModule(source, {
    compilerOptions: {
      jsx: ts.JsxEmit.ReactJSX,
      module: ts.ModuleKind.ESNext,
      target: ts.ScriptTarget.ES2022,
    },
  })
  .outputText.replace(
    /from (["'])([^"']+)\1/g,
    (_, q, name) => `from ${JSON.stringify(import.meta.resolve(name))}`,
  );
const { PolicyReferenceImpact } = await import(
  `data:text/javascript;base64,${Buffer.from(js).toString('base64')}`
);
const render = (value) =>
  renderToStaticMarkup(createElement(PolicyReferenceImpact, { value }));
const value = {
  source: 'requesting_account_quality_annotations',
  labelled_comparisons: 8,
  wanted_comparisons: 6,
  new_false_positives: 2,
  remaining_false_positives: 1,
  resolved_false_positives: 3,
};
test('counts newly introduced errors and does not use second opinions as labels', () => {
  const html = render(value);
  assert.match(html, /2 new false positives/);
  assert.match(html, /1 remain/);
  assert.match(html, /3 resolved/);
  assert.match(html, /6 wanted messages among 8/);
  assert.match(html, /even if observation mode still delivers/);
  assert.match(html, /not reference labels/);
});
test('missing or unavailable wanted labels are unknown, not zero false positives', () => {
  assert.match(
    render({ ...value, wanted_comparisons: 0 }),
    /impact is unknown/,
  );
  assert.doesNotMatch(
    render({ ...value, wanted_comparisons: 0 }),
    /2 new false positives/,
  );
  assert.match(render(undefined), /unavailable/);
  assert.match(render({ ...value, source: 'rspamd' }), /unavailable/);
});
