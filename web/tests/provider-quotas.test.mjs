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
  assert.match(inherited, /Active limits: Unlimited\/min · Unlimited\/day/);
  assert.match(inherited, /Draft limits: 2\/min · 200\/day/);
  assert.ok(!inherited.includes("Unlimited key —"));
  const custom = render({ value: { minute: 0, day: 100 } });
  assert.match(custom, /Draft limits: Unlimited\/min · 100\/day/);
  assert.match(custom, /CRDF Per minute unlimited/);
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
    /Enter a positive integer/,
  );
  assert.equal(
    quotaLabel({ minute: 0, day: 0 }),
    "Unlimited/min · Unlimited/day",
  );
});
test('usage, cooldown and unavailable counters are explicit', () => {
  assert.match(render(), /Usage counters unavailable/);
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
  assert.match(html, /15 this minute · 300 today/);
  assert.match(html, /Provider cooldown/);
  assert.match(html, /including unlimited mode/);
  assert.match(render({ applied: null }), /module disabled/);
});
