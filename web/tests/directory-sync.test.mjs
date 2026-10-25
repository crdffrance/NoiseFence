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
  googleFormError,
  CollectionCoverage,
  DirectorySync,
} = await import(
  await moduleURL('../app/directory-sync.tsx', {
    './directory': directory,
    './client': client,
    './directory-connections': await moduleURL(
      '../app/directory-connections.tsx',
    ),
    './console-ui':
      'data:text/javascript,export function ConfirmDialog({children}){return children};',
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

test('Google form pins the customer and requires explicitly scoped domains and safe tokens', () => {
  const google = { ...source, provider: 'google', authority: 'C01234567' };
  assert.equal(
    googleFormError(google, ['example.test'], 'short-lived-token'),
    null,
  );
  for (const authority of [
    'my_customer',
    'https://admin.googleapis.com',
    'C',
    'c123',
    'C123/path',
    'C123\n',
  ])
    assert.ok(
      googleFormError({ ...google, authority }, ['example.test'], 'token'),
    );
  for (const token of ['', 'Bearer token', 'token\nsecret', 'x'.repeat(8193)])
    assert.ok(googleFormError(google, ['example.test'], token));
  assert.ok(
    googleFormError(
      { ...google, scopes: ['foreign.test'] },
      ['example.test'],
      'token',
    ),
  );
  assert.ok(googleFormError(source, ['example.test'], 'token'));
});

test('coverage makes omitted memberships visible without rendering provider-supplied labels', () => {
  const value = {
    pages: 5,
    requests: 6,
    bytes: 2000,
    excluded_members: {
      external_membership: 2,
      customer_wide_membership: 1,
      '<ScRiPt>': 4,
    },
  };
  const html = renderToStaticMarkup(
    createElement(CollectionCoverage, { value }),
  );
  assert.match(html, /5 pages/);
  assert.match(html, /6 requests/);
  assert.match(html, /External group members/);
  assert.match(html, /Whole-customer memberships/);
  assert.match(html, /Other excluded memberships/);
  assert.doesNotMatch(html, /<script\b/i);
  assert.match(html, /not represented/);
  assert.equal(renderToStaticMarkup(createElement(CollectionCoverage, {})), '');
  const complete = renderToStaticMarkup(
    createElement(CollectionCoverage, {
      value: { ...value, excluded_members: {} },
    }),
  );
  assert.match(complete, /Provider permissions still determine/);
});

const {
  connectionLifetimeError,
  canCollectSaved,
  connectionStatus,
  SavedConnections,
} = await import(await moduleURL('../app/directory-connections.tsx'));
test('saved access keeps unknown, revoked and expired states unavailable', () => {
  const row = {
    source,
    generation: 'synthetic',
    owner: 'admin',
    created: 100,
    expires: 200,
    status: 'configured',
  };
  assert.ok(canCollectSaved(row, 150));
  assert.ok(!canCollectSaved(row, 99));
  assert.ok(!canCollectSaved(row, 200));
  for (const status of [
    'revoked',
    'expired',
    'authorization_changed',
    'not_yet_valid',
    'key_unavailable',
    'configuration_changed',
    'unknown',
  ])
    assert.ok(!canCollectSaved({ ...row, status }, 150));
  assert.equal(connectionStatus('unknown'), 'Unavailable');
  assert.equal(connectionLifetimeError('entra', 129600), null);
  assert.ok(connectionLifetimeError('entra', 129601));
  for (const p of ['google', 'okta']) {
    assert.equal(connectionLifetimeError(p, 60), null);
    assert.ok(connectionLifetimeError(p, 61));
    assert.ok(connectionLifetimeError(p, 1.5));
  }
});
test('saved access display distinguishes persistence from provider success and escapes source metadata', () => {
  const row = {
    source: { ...source, label: '<ScRiPt>alert(1)</ScRiPt>' },
    generation: 'synthetic',
    owner: 'admin',
    created: 100,
    expires: 200,
    status: 'revoked',
  };
  const html = renderToStaticMarkup(
    createElement(SavedConnections, {
      value: { connections: [row], vault: 'ready' },
      busy: false,
      onCollect() {},
      onReplace() {},
      onRevoke() {},
    }),
  );
  assert.match(html, /Revoked/);
  assert.match(html, /does not mean a provider login succeeded/);
  assert.match(html, /The credential is never returned/);
  assert.doesNotMatch(html, /<script\b/i);
  assert.match(html, /disabled=""[^>]*>Collect using saved access/);
});
