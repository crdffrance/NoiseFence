import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import ts from 'typescript';
async function moduleURL(file, bindings = {}) {
  const source = await readFile(new URL(file, import.meta.url), 'utf8');
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
        `from ${JSON.stringify(bindings[specifier] ?? import.meta.resolve(specifier))}`,
    );
  return `data:text/javascript;base64,${Buffer.from(js).toString('base64')}`;
}
const button = await moduleURL('../components/ui/button.tsx', {
  '@/lib/utils': await moduleURL('../lib/utils.ts'),
});
const { ModelManifest, ModelSources } = await import(
  await moduleURL('../app/model-sources.tsx', {
    '@/components/ui/button': button,
    './client': new URL('../app/client.ts', import.meta.url).href,
  })
);
test('model inventory keeps absent files explicit and renders escaped logical slots', () => {
  const html = renderToStaticMarkup(
    createElement(ModelManifest, {
      value: {
        installed: { '/filter/model': { sha256: 'a'.repeat(64), size: 100 } },
        installation: {
          '/filter/model': { sha256: 'b'.repeat(64), size: 105 },
          '<script>': { sha256: 'c'.repeat(64), size: 20 },
        },
      },
    }),
  );
  assert.match(html, /Not included/);
  assert.match(html, /&lt;script&gt;/);
  assert.doesNotMatch(html, /<script>/);
  assert.match(html, /a{64}/);
  assert.match(html, /b{64}/);
  assert.match(html, /Server installation/);
});
test('an empty model set is stated explicitly instead of an empty success table', () => {
  const html = renderToStaticMarkup(
    createElement(ModelManifest, {
      value: { installed: {}, installation: {} },
    }),
  );
  assert.match(html, /No local model files/);
});
test('model selection does not claim quality qualification or silently enroll a cluster', () => {
  const html = renderToStaticMarkup(
    createElement(ModelSources, {
      revision: 1,
      settings: {},
      csrf: 'fixture',
      disabled: false,
      coordinated: false,
      selected: null,
      onSelect: () => {},
    }),
  );
  assert.match(html, /Enable coordinated changes/);
  assert.match(html, /does not automatically select/);
  assert.match(html, /does not demonstrate detection accuracy/);
  assert.match(html, /disabled=""/);
  assert.doesNotMatch(html, /Models activated|Qualified model/);
});
