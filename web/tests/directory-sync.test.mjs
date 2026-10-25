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
  awsFormError,
  adFormError,
  parseAdEnvelope,
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
  assert.match(
    html,
    /Scheduled collection requires a separate, expiring authorization/,
  );
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
  scheduleError,
  scheduleStatus,
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

test('automatic collection requires the access owner and a bounded finite authorization', () => {
  const entry = {
    source,
    status: 'configured',
    owner: 'admin',
    created: 100,
    expires: 4000,
  };
  assert.equal(scheduleError(entry, 'admin', 15, 1000, 200), null);
  for (const [user, interval, end] of [
    ['other', 15, 1000],
    ['admin', 14, 1000],
    ['admin', 1441, 1000],
    ['admin', 15.5, 1000],
    ['admin', 15, 200],
    ['admin', 15, 4001],
    ['admin', 15, NaN],
  ])
    assert.ok(scheduleError(entry, user, interval, end, 200));
  assert.ok(
    scheduleError({ ...entry, status: 'revoked' }, 'admin', 15, 1000, 200),
  );
  assert.equal(scheduleStatus('awaiting_review'), 'Candidate awaiting review');
  assert.equal(scheduleStatus('invented'), 'Unavailable');
});
test('schedule summary distinguishes candidate review and does not imply activation', () => {
  const html = renderToStaticMarkup(
    createElement(SavedConnections, {
      value: {
        vault: 'ready',
        connections: [
          {
            source,
            owner: 'admin',
            created: 100,
            expires: 4000,
            status: 'configured',
            generation: 'generation',
            schedule: {
              id: 'grant',
              interval_seconds: 900,
              expires: 2000,
              next_due: 1000,
              revoked_at: null,
              state: 'awaiting_review',
              last_run: { request: { id: 'job' }, state: 'ready' },
            },
          },
        ],
      },
      username: 'admin',
      onCollect() {},
      onReplace() {},
      onRevoke() {},
      onSchedule() {},
      onStopSchedule() {},
      onInspect() {},
    }),
  );
  assert.match(html, /Candidate awaiting review/);
  assert.match(html, /Nothing has been activated automatically/);
  assert.match(html, /View last collection/);
  assert.match(html, /Stop automatic collection/);
});

test('AWS form requires a fixed store, temporary key and separate session token', () => {
  const aws = {
    ...source,
    provider: 'aws_identity_store',
    authority: 'eu-west-3:d-1234567890',
  };
  const access = 'ASIA' + 'A'.repeat(16),
    secret = 'a'.repeat(40),
    token = 'fixture-token';
  assert.equal(
    awsFormError(aws, ['example.test'], access, secret, token),
    null,
  );
  for (const authority of [
    'https://example.test',
    'eu-west-3:d-1234567890:evil',
    'us-gov-east-1:d-1234567890',
    'eu-west-3:00000000-0000-0000-0000-000000000000',
  ])
    assert.ok(
      awsFormError(
        { ...aws, authority },
        ['example.test'],
        access,
        secret,
        token,
      ),
    );
  for (const [a, s, t] of [
    ['AKIA' + 'A'.repeat(16), secret, token],
    [access, secret, ''],
    [access, secret, 'bad\ntoken'],
    [access, 'a'.repeat(41), token],
  ])
    assert.ok(awsFormError(aws, ['example.test'], a, s, t));
  assert.ok(
    awsFormError(
      { ...aws, scopes: ['other.test'] },
      ['example.test'],
      access,
      secret,
      token,
    ),
  );
});

test('AD enrollment is source-bound, public-only and separate from pull schedules', async () => {
  const fixture = JSON.parse(
    await readFile(
      new URL(
        '../../tests/fixtures/identity/ad-signed-export.json',
        import.meta.url,
      ),
      'utf8',
    ),
  );
  const ad = {
    ...source,
    provider: 'active_directory',
    authority: 'corp.example:2905b910-836f-4466-bba4-ae2a00661c74',
  };
  assert.equal(adFormError(ad, ['example.test'], fixture.public_key), null);
  for (const authority of [
    'corp.example',
    'https://dc.corp.example',
    'corp.example:00000000-0000-0000-0000-000000000000',
  ])
    assert.ok(
      adFormError({ ...ad, authority }, ['example.test'], fixture.public_key),
    );
  assert.ok(adFormError(ad, ['example.test'], 'PRIVATE KEY'));
  assert.ok(
    adFormError(
      { ...ad, scopes: ['foreign.test'] },
      ['example.test'],
      fixture.public_key,
    ),
  );
  assert.equal(connectionLifetimeError('active_directory', 129600), null);
  assert.ok(connectionLifetimeError('active_directory', 129601));
  const entry = {
    source: ad,
    generation: 'synthetic',
    owner: 'admin',
    created: 100,
    expires: 1000,
    status: 'configured',
  };
  assert.match(
    scheduleError(entry, 'admin', 15, 1000, 200),
    /cannot authorize a pull/,
  );
  const html = renderToStaticMarkup(
    createElement(SavedConnections, {
      value: { connections: [entry], vault: 'ready' },
      busy: false,
      username: 'admin',
    }),
  );
  assert.match(html, /Upload signed AD export/);
  assert.match(html, /Replace verification key/);
  assert.doesNotMatch(
    html,
    /Set up automatic collection|Collect using saved access/,
  );
  assert.equal(
    parseAdEnvelope(JSON.stringify(fixture.envelope)).id,
    fixture.envelope.id,
  );
  for (const patch of [
    { id: 'wrong' },
    { protocol: 'other' },
    { private_key: 'do-not-upload' },
    { key_id: 'wrong' },
    { payload: {} },
  ])
    assert.throws(() =>
      parseAdEnvelope(JSON.stringify({ ...fixture.envelope, ...patch })),
    );
});
