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
  protectionEdit,
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

test('provider protection edits contain only changed assignments, without provider attributes', () => {
  const before = newDirectory(['example.test']);
  before.source.provider = 'entra';
  before.source.id = 'provider';
  before.people = [
    alice,
    { ...alice, id: 'delegate', addresses: ['d@example.test'] },
  ];
  before.groups = [
    {
      id: 'finance',
      display_name: 'Finance',
      addresses: [],
      activity: 'active',
      protected: true,
    },
  ];
  const after = structuredClone(before);
  after.people[0].protected_roles = ['executive'];
  after.groups[0].protected = false;
  after.delegations = [
    { owner: alice.id, delegate: 'delegate', address: alice.addresses[0] },
  ];
  assert.deepEqual(protectionEdit(before, after), {
    operation: 'update_protection',
    source_id: 'provider',
    patch: {
      people: [{ id: alice.id, roles: ['executive'] }],
      groups: [{ id: 'finance', protected: false }],
      add_delegations: after.delegations,
      remove_delegations: [],
    },
  });
  const removal = protectionEdit(after, before);
  assert.deepEqual(removal.patch.remove_delegations, after.delegations);
  assert.throws(() => protectionEdit(before, before), /between 1 and 100/);
  for (const change of [
    (d) => (d.people[0].display_name = 'Forged'),
    (d) => (d.people[0].addresses = ['forged@example.test']),
    (d) => (d.people[0].activity = 'inactive'),
    (d) => (d.people[0].kind = 'supplier'),
    (d) => (d.people[1].id = alice.id),
    (d) => d.people.pop(),
    (d) => (d.groups[0].addresses = ['forged@example.test']),
    (d) =>
      d.memberships.push({
        group: 'finance',
        member: { kind: 'person', id: alice.id },
      }),
    (d) => (d.source.scopes = ['other.test']),
    (d) => d.delegations.push(d.delegations[0]),
  ]) {
    const invalid = structuredClone(after);
    change(invalid);
    assert.throws(
      () => protectionEdit(before, invalid),
      /Provider data changed/,
    );
  }
  assert.deepEqual(before.people[0], alice);
});
test('large source sends a bounded patch and refuses more than 100 simultaneous assignments', () => {
  const before = newDirectory(['example.test']);
  before.people = Array.from({ length: 20000 }, (_, i) => ({
    ...alice,
    id: `id-${i}`,
  }));
  const after = structuredClone(before);
  for (let i = 0; i < 100; ++i) after.people[i].protected_roles = ['supplier'];
  const edit = protectionEdit(before, after);
  assert.equal(edit.patch.people.length, 100);
  assert.ok(JSON.stringify(edit).length < 10000);
  after.people[100].protected_roles = [];
  assert.throws(() => protectionEdit(before, after), /between 1 and 100/);
});
test('provider demo protects local roles without renewing the last successful sync', async () => {
  const fixture = administrationFixture(
    new URLSearchParams('administration=identity&directory=provider'),
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
  draft.people[0].protected_roles = ['legal'];
  draft.delegations[0].delegate = 'operations-002';
  const prepared = await fixture('/admin/identity/prepare', {
    method: 'POST',
    body: JSON.stringify({
      revision: 25,
      catalog_sha256: before.catalog_sha256,
      edit: protectionEdit(before.draft, draft),
    }),
  }).json();
  assert.equal(prepared.active, false);
  assert.equal(prepared.review.operation, 'protection');
  assert.equal(prepared.review.delegation_changes, 2);
  assert.equal(
    prepared.review.before.completed_at,
    prepared.review.after.completed_at,
  );
  assert.deepEqual((await get()).draft, before.draft);
  await fixture('/admin/config', {
    method: 'POST',
    body: JSON.stringify({
      revision: 25,
      settings: { ...base.settings, identity_directory: prepared.selection },
    }),
  }).json();
  const view = await get();
  assert.deepEqual(view.draft.people[0].protected_roles, ['legal']);
  assert.equal(view.sources[0].completed_at, before.sources[0].completed_at);
  assert.deepEqual(view.draft.memberships, before.draft.memberships);
});
