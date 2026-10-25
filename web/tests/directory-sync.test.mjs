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
      (_, q, s) =>
        `from ${JSON.stringify(bindings[s] ?? import.meta.resolve(s))}`,
    );
  return `data:text/javascript;base64,${Buffer.from(js).toString('base64')}`;
}

const directory = await moduleURL('../app/directory.ts');
const client =
  'data:text/javascript,export async function api(){throw new Error("No live requests in tests")};';
const {
  syncMessage,
  canReviewSync,
  entraFormError,
  oktaFormError,
  DirectorySync,
} = await import(
  await moduleURL('../app/directory-sync.tsx', {
    './directory': directory,
    './client': client,
  })
);
const source = {
  id: 'entra',
  label: 'Organization',
  provider: 'entra',
  authority: '11111111-1111-4111-8111-111111111111',
  scopes: ['example.test'],
  stale_after_seconds: 86400,
};
const prepared = {
  revision: 4,
  selection: { sha256: 'a'.repeat(64), reviewed_from: null },
  active: false,
};
const job = {
  id: 'j',
  source_id: 'entra',
  state: 'ready',
  stale: false,
  reason: null,
  prepared,
};
test('sync review is bound to the exact installed revision and complete receipt', () => {
  assert.ok(canReviewSync(job, 4, null));
  for (const patch of [
    { state: 'running' },
    { state: 'outcome_unknown' },
    { state: 'failed' },
    { state: 'future' },
    { stale: true },
    { installed: true },
    { prepared: null },
  ])
    assert.ok(!canReviewSync({ ...job, ...patch }, 4, null));
  assert.ok(!canReviewSync(job, 5, null));
  assert.ok(!canReviewSync(job, 4, 'b'.repeat(64)));
  assert.match(
    syncMessage({ ...job, state: 'outcome_unknown' }),
    /No completion receipt/,
  );
  assert.doesNotMatch(
    syncMessage({ ...job, state: 'outcome_unknown' }),
    /failed|stopped/,
  );
  assert.match(syncMessage({ ...job, stale: true }), /older configuration/);
});
test('Entra form rejects unscoped sources and non-UUID authority or application', () => {
  const id = source.authority;
  assert.equal(entraFormError(source, ['example.test'], id, 'secret'), null);
  for (const [s, c, k] of [
    [{ ...source, provider: 'manual' }, id, 'secret'],
    [{ ...source, scopes: ['other.test'] }, id, 'secret'],
    [{ ...source, authority: 'evil.example' }, id, 'secret'],
    [source, 'bad', 'secret'],
    [source, id, ''],
  ])
    assert.ok(entraFormError(s, ['example.test'], c, k));
});
test('initial sync interface identifies one-shot collection and secret non-persistence', () => {
  const html = renderToStaticMarkup(
    createElement(DirectorySync, {
      user: { username: 'admin' },
      revision: 4,
      installed: null,
      domains: ['example.test'],
      sources: [],
      disabled: false,
      visible: true,
      onPrepared() {},
      onDirty() {},
      onBusy() {},
    }),
  );
  assert.match(html, /one-time collection/);
  assert.match(html, /not saved in settings/);
  assert.match(html, /Scheduled synchronization is not enabled/);
  assert.doesNotMatch(html, /Connected|Successfully synchronized/);
});

test('Okta form pins the org and rejects scopes, token prefixes and secret injection', () => {
  const okta = { ...source, provider: 'okta', authority: 'company.okta.com' };
  assert.equal(oktaFormError(okta, ['example.test'], 'opaque-token'), null);
  for (const authority of [
    'evil.test',
    'https://company.okta.com',
    'company.okta.com.evil.test',
    'x.y.okta.com',
    '-x.okta.com',
    'x-.okta.com',
  ])
    assert.ok(oktaFormError({ ...okta, authority }, ['example.test'], 'token'));
  for (const token of ['', 'Bearer token', 'token\nsecret', 'x'.repeat(8193)])
    assert.ok(oktaFormError(okta, ['example.test'], token));
  assert.ok(
    oktaFormError(
      { ...okta, scopes: ['other.test'] },
      ['example.test'],
      'token',
    ),
  );
  assert.ok(oktaFormError(source, ['example.test'], 'token'));
});
