import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import ts from 'typescript';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

const source = await readFile(
  new URL('../app/url-resolution.tsx', import.meta.url),
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
const { UrlResolutionDetails } = await import(
  `data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`
);
const render = (report) =>
  renderToStaticMarkup(createElement(UrlResolutionDetails, { report }));
const base = {
  version: 'url-resolution-1',
  settings_sha256: 'hash',
  elapsed_ms: 20,
  omitted: 0,
  chains: [],
};

test('an unavailable local inventory is distinct from a forbidden destination', () => {
  const html = render({
    ...base,
    local_inventory_available: false,
    chains: [
      {
        source_sha256: 'hash',
        complete: false,
        detail: 'network',
        hops: [],
      },
    ],
  });
  assert.match(html, /Inventaire réseau du serveur indisponible/);
  assert.doesNotMatch(html, /adresse interne, réservée ou exclue bloqué/);
});

test('historical messages do not invent a URL visit', () => {
  assert.equal(render(undefined), '');
  assert.equal(render(null), '');
});
test('a followed chain reports HTTP arrival, not a safe URL verdict', () => {
  const html = render({
    ...base,
    chains: [
      {
        source_sha256: 'hash',
        complete: true,
        detail: null,
        hops: [
          { url_sha256: 'a', site: 'example.com', code: 302 },
          { url_sha256: 'b', site: 'example.org', code: 200 },
        ],
      },
    ],
  });
  assert.match(html, /Destination HTTP atteinte/);
  assert.match(html, /ne signifie pas que le lien est sûr/);
  assert.match(html, /example.com \(302\).*example.org \(200\)/);
  assert.ok(!html.includes('<a '));
});
test('blocked and omitted URLs are visibly incomplete and server text is escaped', () => {
  const html = render({
    ...base,
    omitted: 2,
    chains: [
      {
        source_sha256: 'hash',
        complete: false,
        detail: 'forbidden_address',
        hops: [
          { url_sha256: 'a', site: '<img src=x onerror=alert(1)>', code: 302 },
        ],
      },
    ],
  });
  assert.match(html, /Parcours incomplet/);
  assert.match(html, /non parcouru/);
  assert.match(html, /interne, réservée ou exclue bloqué/);
  assert.ok(html.includes('&lt;img'));
  assert.ok(!html.includes('<img'));
});
test('JavaScript navigation is not presented as a completed resolution', () => {
  assert.match(
    render({
      ...base,
      chains: [
        {
          source_sha256: 'hash',
          complete: false,
          detail: 'client_script',
          hops: [],
        },
      ],
    }),
    /navigation éventuelle n’est pas exécutée/,
  );
});
