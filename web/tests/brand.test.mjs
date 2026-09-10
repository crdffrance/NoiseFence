import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import ts from 'typescript';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

const source = await readFile(
  new URL('../app/brand.tsx', import.meta.url),
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
    /from ["'](react\/jsx-runtime|lucide-react)["']/g,
    (_, specifier) => `from ${JSON.stringify(import.meta.resolve(specifier))}`,
  );
const { ScoreMeter } = await import(
  `data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`
);
const render = (score) =>
  renderToStaticMarkup(createElement(ScoreMeter, { score }));

test('missing or invalid suspicion is unavailable, while a real zero retains a semantic meter', () => {
  for (const value of [null, NaN, Infinity, -Infinity]) {
    assert.match(render(value), /Indice indisponible/);
    assert.doesNotMatch(render(value), /<meter/);
  }
  assert.match(
    render(0),
    /<meter[^>]*aria-label="Indice de suspicion"[^>]*value="0"/,
  );
  assert.match(render(0), />0\.0</);
});

test('the suspicion scale remains bounded without hiding the reported value', () => {
  assert.match(render(98.7), /value="98\.7"/);
  assert.match(render(-1), /value="0"/);
  assert.match(render(101), /value="100"/);
  assert.match(render(101), />101\.0</);
});
