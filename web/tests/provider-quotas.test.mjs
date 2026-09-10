import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import ts from 'typescript';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

const source = await readFile(
  new URL('../app/provider-quotas.tsx', import.meta.url),
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
const { ProviderQuotas, numericQuota, quotaLabel } = await import(
  `data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`
);
const base = {
  name: 'CRDF',
  bootstrap: { minute: 2, day: 200 },
  applied: { minute: 0, day: 0 },
  onChange: () => {},
};
const render = (props = {}) =>
  renderToStaticMarkup(createElement(ProviderQuotas, { ...base, ...props }));
test('explicit unlimited is distinct from inherited budgets and current server state', () => {
  const inherited = render();
  assert.match(inherited, /Actifs : Illimité\/min · Illimité\/jour/);
  assert.match(inherited, /À appliquer : 2\/min · 200\/jour/);
  assert.ok(!inherited.includes('Clé illimitée —'));
  const custom = render({ value: { minute: 0, day: 100 } });
  assert.match(custom, /À appliquer : Illimité\/min · 100\/jour/);
  assert.match(custom, /CRDF Par minute illimité/);
});
test('empty, zero and malformed numeric fields cannot silently grant unlimited', () => {
  for (const value of [
    '',
    ' ',
    '0',
    '-1',
    '1.5',
    'NaN',
    'Infinity',
    '4294967296',
  ])
    assert.equal(numericQuota(value), -1);
  assert.equal(numericQuota('120'), 120);
  assert.equal(numericQuota('4294967295'), 4294967295);
  assert.match(
    render({ value: { minute: -1, day: 200 } }),
    /Saisissez un entier positif/,
  );
  assert.equal(
    quotaLabel({ minute: 0, day: 0 }),
    'Illimité/min · Illimité/jour',
  );
});
test('usage, cooldown and unavailable counters are explicit', () => {
  assert.match(render(), /Compteurs indisponibles/);
  const html = render({
    value: { minute: 0, day: 0 },
    usage: {
      minute_used: 15,
      day_used: 300,
      minute_resets_at: 1800000060,
      day_resets_at: 1800057600,
      cooldown_until: 1800000300,
    },
  });
  assert.match(html, /15 cette minute · 300 aujourd’hui/);
  assert.match(html, /Pause fournisseur/);
  assert.match(html, /y compris en mode illimité/);
  assert.match(render({ applied: null }), /module désactivé/);
});
