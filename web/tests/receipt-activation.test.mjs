import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import ts from 'typescript';
const source = await readFile(
  new URL('../app/receipt-activation.tsx', import.meta.url),
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
    (_, _quote, specifier) =>
      `from ${JSON.stringify(import.meta.resolve(specifier))}`,
  );
const { ReceiptActivation } = await import(
  `data:text/javascript;base64,${Buffer.from(js).toString('base64')}`
);
const render = (epoch) =>
  renderToStaticMarkup(createElement(ReceiptActivation, { epoch }));
const epoch = { sequence: 7, revision: 12, digest: 'a'.repeat(64) };
test('receipt panel renders the complete recorded identity without a current-config fallback', () => {
  const html = render(epoch);
  assert.match(html, /Configuration revision<\/dt><dd>12/);
  assert.match(html, /Activation sequence<\/dt><dd>7/);
  assert.ok(html.includes(epoch.digest));
  assert.match(html, /does not certify detection quality/);
});
test('missing historical identity stays explicitly unrecorded', () => {
  for (const missing of [null, undefined]) {
    assert.match(render(missing), /Not recorded for this message/);
    assert.match(render(missing), /Current settings are not substituted/);
  }
});
test('invalid or rounded JSON numbers never render a fabricated identity', () => {
  for (const invalid of [
    { ...epoch, sequence: Number.MAX_SAFE_INTEGER + 1 },
    { ...epoch, revision: Number.MAX_SAFE_INTEGER + 1 },
    { ...epoch, revision: -1 },
    { ...epoch, sequence: 1.5 },
    { ...epoch, digest: '<script>bad</script>' },
  ]) {
    const html = render(invalid);
    assert.match(html, /cannot be displayed reliably/);
    assert.doesNotMatch(html, /<script>|Configuration revision<\/dt>/);
  }
});
