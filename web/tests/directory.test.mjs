import assert from 'node:assert/strict';
import test from 'node:test';
import {
  addressList,
  identityError,
  sourceError,
  newDirectory,
  parsePeopleCsv,
  mergePeople,
  removePerson,
  removeGroup,
  preparedMatches,
  directoryPending,
} from '../app/directory.ts';
import { administrationFixture } from '../demo-administration.mjs';
const header = 'id,name,addresses,kind,activity,roles\r\n';
const row =
  'p1,"Équipe, Finance",Alex+tag@example.test;Alex@EXAMPLE.TEST,person,active,finance;legal';
const alice = parsePeopleCsv(header + row)[0];
test('directory imports preserve stable IDs and local-part identity and handle quoted UTF-8', () => {
  assert.equal(alice.display_name, 'Équipe, Finance');
  assert.deepEqual(alice.addresses, [
    'Alex+tag@example.test',
    'Alex@example.test',
  ]);
  assert.deepEqual(alice.protected_roles, ['finance', 'legal']);
  assert.deepEqual(
    addressList(
      'Alex+tag@EXAMPLE.TEST\nalex@example.test;Alex+tag@example.test',
    ),
    ['Alex+tag@example.test', 'alex@example.test'],
  );
  assert.deepEqual(parsePeopleCsv('\uFEFF' + header + row), [alice]);
});
test('invalid CSV is rejected as a whole, including unknown role and repeated immutable IDs', () => {
  for (const input of [
    '',
    header,
    header + row + '\r\n' + row,
    header + row.replace('finance;legal', 'administrator'),
    header + row.replace(',active,', ',connected,'),
    header + row + 'extra',
    header + row.replace('"Équipe, Finance"', '"unclosed'),
    header + 'p1,Alice" Finance,a@b.test,person,active,finance',
    header + row + '\r\nunknown',
  ])
    assert.throws(() => parsePeopleCsv(input));
  assert.throws(() => parsePeopleCsv('x'.repeat(4 * 1024 * 1024 + 1)), /4 MiB/);
  assert.throws(
    () =>
      parsePeopleCsv(
        header + `p1,${'a'.repeat(16385)},a@b.test,person,active,`,
      ),
    /16 KiB/,
  );
});
test('manual source scope and identity validation refuse ambiguity in the input shape', () => {
  const d = newDirectory(['example.test']);
  d.source.id = 'manual';
  d.source.label = 'Organization';
  assert.equal(sourceError(d.source, ['example.test']), null);
  assert.ok(
    sourceError({ ...d.source, scopes: ['another.test'] }, ['example.test']),
  );
  assert.ok(sourceError({ ...d.source, provider: 'entra' }, ['example.test']));
  assert.ok(
    sourceError({ ...d.source, stale_after_seconds: 0 }, ['example.test']),
  );
  assert.ok(identityError({ ...alice, display_name: 'a\u202eb' }));
  assert.ok(identityError({ ...alice, display_name: 'é'.repeat(101) }));
});
test('CSV merges only matching stable IDs and preserves unrelated identities', () => {
  const bob = { ...alice, id: 'p2', display_name: 'Bob' };
  const next = { ...alice, display_name: 'Alice Updated' };
  assert.deepEqual(mergePeople([alice, bob], [next]), {
    added: 0,
    changed: 1,
    people: [next, bob],
  });
  assert.equal(alice.display_name, 'Équipe, Finance');
  assert.deepEqual(mergePeople([bob], [alice]), {
    added: 1,
    changed: 0,
    people: [bob, alice],
  });
});
test('removal clears only references to the removed identity or group', () => {
  const d = newDirectory(['example.test']);
  d.people = [alice, { ...alice, id: 'p2' }];
  d.groups = [
    {
      id: 'g',
      display_name: 'Group',
      activity: 'active',
      addresses: [],
      protected: true,
    },
    {
      id: 'child',
      display_name: 'Child',
      activity: 'active',
      addresses: [],
      protected: false,
    },
  ];
  d.memberships = [
    { group: 'g', member: { kind: 'person', id: 'p1' } },
    { group: 'g', member: { kind: 'person', id: 'p2' } },
    { group: 'g', member: { kind: 'group', id: 'child' } },
  ];
  d.delegations = [
    { owner: 'p1', delegate: 'p2', address: alice.addresses[0] },
  ];
  const next = removePerson(d, 'p1');
  assert.equal(next.people.length, 1);
  assert.equal(next.memberships.length, 2);
  assert.equal(next.delegations.length, 0);
  assert.equal(d.people.length, 2);
  assert.equal(removeGroup(d, 'child').memberships.length, 2);
  assert.equal(removeGroup(d, 'g').memberships.length, 0);
});
test('prepared changes bind both revision and installed digest; unchanged settings are not pending', () => {
  const p = {
    active: false,
    revision: 25,
    selection: { sha256: 'b', reviewed_from: 'a' },
  };
  assert.ok(preparedMatches(p, 25, 'a'));
  assert.equal(preparedMatches(p, 26, 'a'), false);
  assert.equal(preparedMatches(p, 25, 'c'), false);
  assert.equal(preparedMatches({ ...p, active: true }, 25, 'a'), false);
  assert.equal(directoryPending(null, 'a'), false);
  assert.equal(directoryPending({ sha256: 'a' }, 'a'), false);
  assert.ok(directoryPending({ sha256: 'b' }, 'a'));
  assert.ok(directoryPending({ sha256: null }, 'a'));
});
test('browser fixture keeps prepared directory separate from installed settings until policy application', async () => {
  const fixture = administrationFixture(
    new URLSearchParams('administration=identity'),
    {
      filters: { threshold: 95 },
      actions: { quarantine_days: 14 },
      rbl: { minimum_providers: 2 },
    },
    'preview',
  );
  const base = await fixture('/admin/config').json();
  const get = () =>
    fixture(
      '/admin/identity',
      undefined,
      new URL('http://localhost/?source=organization'),
    ).json();
  const before = await get();
  const draft = structuredClone(before.draft);
  draft.people[0].display_name = 'Updated';
  const prepared = await fixture('/admin/identity/prepare', {
    method: 'POST',
    body: JSON.stringify({
      revision: 25,
      catalog_sha256: before.catalog_sha256,
      edit: { operation: 'upsert_manual', draft },
    }),
  }).json();
  assert.equal(prepared.active, false);
  assert.equal((await get()).draft.people[0].display_name, 'Alex Morgan');
  assert.equal(prepared.review.people.changed, 1);
  await fixture('/admin/config', {
    method: 'POST',
    body: JSON.stringify({
      revision: 25,
      settings: { ...base.settings, identity_directory: prepared.selection },
    }),
  }).json();
  assert.equal((await get()).draft.people[0].display_name, 'Updated');
  assert.equal((await get()).revision, 26);
});

import { settingTitle } from '../app/settings-review.ts';
test('policy comparison identifies both directory digests explicitly', () => {
  assert.equal(
    settingTitle(['identity_directory', 'sha256']),
    'Prepared catalog SHA-256',
  );
  assert.equal(
    settingTitle(['identity_directory', 'reviewed_from']),
    'Reviewed installed catalog SHA-256',
  );
});
