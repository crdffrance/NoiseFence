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
const bindings = {
  '@/components/ui/button': button,
  './client': new URL('../app/client.ts', import.meta.url).href,
};
const { CatalogTable, CatalogQualification, ModelCatalog } = await import(
  await moduleURL('../app/model-catalog.tsx', {
    ...bindings,
    './model-sources': await moduleURL('../app/model-sources.tsx', bindings),
  })
);
test('retained model names are escaped and provenance is not a qualification claim', () => {
  const html = renderToStaticMarkup(
    createElement(CatalogTable, {
      entries: [
        {
          id: 'a'.repeat(64),
          label: '<script>example</script>',
          source_build: '0.28.0-rc.3',
          source_revision: 4,
          files: { '/filter/model': { sha256: 'b'.repeat(64), size: 1024 } },
        },
      ],
      disabled: true,
      onPreview: () => {},
      onRemove: () => {},
    }),
  );
  assert.match(html, /&lt;script&gt;/);
  assert.doesNotMatch(html, /<script>/);
  assert.match(html, /Source revision 4/);
  assert.match(html, /1,024 bytes/);
  assert.match(html, /Preview for this draft/);
  assert.match(html, /Remove retained copy/);
  assert.match(html, /disabled=""/);
  assert.doesNotMatch(html, /Qualified|Activated/);
});
test('passing report contracts do not certify independent whole-pipeline quality', () => {
  const html = renderToStaticMarkup(
    createElement(CatalogQualification, {
      value: {
        whole_pipeline: 'not_evaluated',
        fusion_validation: 'report_contract_valid',
      },
    }),
  );
  assert.match(html, /Whole-pipeline qualification: not evaluated/);
  assert.match(html, /does not independently certify/);
  assert.match(html, /compatibility with this draft/);
  assert.match(html, /Observation and existing activation requirements/);
});
test('stale and unknown report statuses never imply authority for decision mode', () => {
  const stale = renderToStaticMarkup(
    createElement(CatalogQualification, {
      value: { fusion_validation: 'invalid_or_stale' },
    }),
  );
  assert.match(stale, /cannot authorize decision mode/);
  for (const status of [
    '<script>unknown</script>',
    'constructor',
    '__proto__',
  ]) {
    const unknown = renderToStaticMarkup(
      createElement(CatalogQualification, {
        value: { fusion_validation: status },
      }),
    );
    assert.match(unknown, /unavailable/);
    assert.doesNotMatch(unknown, /<script>/);
  }
});
test('catalog has explicit enrollment, backup and draft-selection semantics', () => {
  const html = renderToStaticMarkup(
    createElement(ModelCatalog, {
      revision: 1,
      settings: {},
      csrf: 'fixture',
      disabled: false,
      coordinated: false,
      selected: 'a'.repeat(64),
      onSelect: () => {},
    }),
  );
  assert.match(html, /Enable coordinated changes/);
  assert.match(html, /included in its backups/);
  assert.match(html, /selection is a draft/);
  assert.match(html, /Clear model selection/);
  assert.match(html, /does not delete installed models/);
});
