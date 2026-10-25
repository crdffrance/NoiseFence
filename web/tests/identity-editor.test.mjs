import assert from 'node:assert/strict';
import test from 'node:test';
import {
  parseIdentityCsv,
  previewIdentityImport,
  protectedNameError,
  protectedNameConflicts,
  matchesProtectedName,
} from '../app/identity-editor.ts';
const alice = { name: 'Alice Finance', domain: 'example.test' };
test('CSV handles BOM, CRLF, quotes and non-ASCII display names without altering them', () => {
  assert.deepEqual(
    parseIdentityCsv(
      '\uFEFFname,domain\r\n"Équipe, ""Finance""",EXAMPLE.TEST\r\n',
    ),
    [{ name: 'Équipe, "Finance"', domain: 'example.test' }],
  );
});
test('CSV rejects malformed quoting, extra/missing columns and an empty document', () => {
  for (const text of [
    '',
    'name,domain\n',
    'name,email\nAlice,example.test',
    'name,domain\nAlice',
    'name,domain\nAlice,example.test,x',
    'name,domain\n"Alice,example.test',
    'name,domain\n"Alice"x,example.test',
    'name,domain\nAli"ce,example.test',
  ])
    assert.throws(() => parseIdentityCsv(text));
});
test('CSV is bounded before and during parsing', () => {
  assert.throws(() => parseIdentityCsv('x'.repeat(65537)), /64 KiB/);
  assert.throws(
    () =>
      parseIdentityCsv('name,domain\n' + 'Alice,example.test\n'.repeat(101)),
    /100 names/,
  );
  assert.equal(
    parseIdentityCsv('name,domain\n' + 'Alice,example.test\n'.repeat(100))
      .length,
    100,
  );
});
test('names respect UTF-8 byte limits and reject controls and bidi disguises', () => {
  assert.equal(
    protectedNameError({ name: 'é'.repeat(50), domain: 'example.test' }),
    null,
  );
  for (const name of [
    'Al',
    'é'.repeat(51),
    'Alice\nFinance',
    'Alice\u202EFinance',
    'Alice\u0000',
  ])
    assert.ok(protectedNameError({ name, domain: 'example.test' }));
  assert.throws(
    () => parseIdentityCsv('name,domain\n"Alice\nFinance",example.test'),
    /control/,
  );
});
test('domains require exact DNS syntax without URLs, addresses or wildcards', () => {
  for (const domain of [
    'https://example.test',
    'a@example.test',
    '*.example.test',
    'example.test.',
    '-x.test',
    'x-.test',
    'x..test',
    'é.test',
    'a'.repeat(64) + '.test',
  ])
    assert.ok(protectedNameError({ name: 'Alice', domain }));
  for (const domain of [
    'EXAMPLE.TEST',
    'mx1.example.test',
    'xn--bcher-kva.test',
    'localhost',
  ])
    assert.equal(protectedNameError({ name: 'Alice', domain }), null);
});
test('import appends and deduplicates after normalization without mutating input', () => {
  const existing = [alice],
    incoming = [
      { name: ' ALICE FINANCE ', domain: 'EXAMPLE.TEST' },
      { name: 'Bob Finance', domain: 'example.test' },
      { name: 'Bob Finance', domain: 'example.test' },
    ];
  assert.deepEqual(previewIdentityImport(incoming, existing), {
    duplicates: 2,
    additions: [{ name: 'Bob Finance', domain: 'example.test' }],
  });
  assert.deepEqual(existing, [alice]);
  assert.equal(incoming[0].name, ' ALICE FINANCE ');
});
test('import validates the combined capacity, including existing rows', () => {
  assert.throws(
    () =>
      previewIdentityImport(
        [alice],
        Array.from({ length: 100 }, (_, i) => ({
          name: `Person ${i}`,
          domain: 'example.test',
        })),
      ),
    /exceed/,
  );
});
test('same-name mappings to different domains are not treated as an allowlist', () => {
  const other = { name: 'alice finance', domain: 'other.test' };
  assert.throws(
    () => previewIdentityImport([other], [alice]),
    /more than one domain/,
  );
  assert.throws(
    () => previewIdentityImport([alice, other], []),
    /more than one domain/,
  );
  assert.deepEqual(protectedNameConflicts([alice, other]), ['alice finance']);
});
test('recompute preview after parent changes rather than committing a stale list', () => {
  assert.equal(previewIdentityImport([alice], []).additions.length, 1);
  assert.equal(previewIdentityImport([alice], [alice]).additions.length, 0);
  assert.throws(() =>
    previewIdentityImport([alice], [{ ...alice, domain: 'other.test' }]),
  );
});
test('search is case insensitive and searches names and domains', () => {
  assert.ok(matchesProtectedName(alice, 'FINANCE'));
  assert.ok(matchesProtectedName(alice, ' EXAMPLE.TEST '));
  assert.equal(matchesProtectedName(alice, 'nobody'), false);
});

import { settingTitle } from '../app/settings-review.ts';
test('configuration review names identity changes rather than showing a bare array index', () => {
  assert.equal(
    settingTitle(['protection', 'protected_names', '2']),
    'Protected name 3',
  );
  assert.equal(
    settingTitle(['protection', 'protected_names', '2', 'domain']),
    'Protected name 3 · sending domain',
  );
  assert.equal(
    settingTitle(['protection', 'identity']),
    'Observe identity signals',
  );
});
