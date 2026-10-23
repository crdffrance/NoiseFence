import test from 'node:test';
import assert from 'node:assert/strict';
import {
  settingChanges,
  changePath,
  settingValue,
  auditRevision,
  auditDescription,
  keepsConfigurationDraft,
} from '../app/settings-review.ts';
test('configuration comparison covers changed, removed and newly present fields including future settings', () => {
  const before = {
    filters: { threshold: 95, mode: 'observe' },
    actions: { spam: 'deliver' },
    future: { flag: null },
    obsolete: 1,
  };
  const after = {
    filters: { threshold: 98, mode: 'observe' },
    actions: { spam: 'quarantine' },
    future: { flag: false },
    newField: null,
  };
  const rows = settingChanges(before, after);
  assert.deepEqual(
    rows.map((r) => changePath(r.path)),
    [
      '/actions/spam',
      '/filters/threshold',
      '/future/flag',
      '/newField',
      '/obsolete',
    ],
  );
  assert.equal(rows.find((r) => r.path[0] === 'obsolete').after, undefined);
  assert.equal(rows.find((r) => r.path[0] === 'newField').after, null);
  assert.equal(settingValue(undefined), 'Not set');
  assert.equal(settingValue(null), 'null');
  assert.equal(settingValue(false), 'false');
});
test('object serialization order is irrelevant, while route and rule array order is retained', () => {
  assert.deepEqual(
    settingChanges({ a: 1, b: { x: 2, y: 3 } }, { b: { y: 3, x: 2 }, a: 1 }),
    [],
  );
  assert.deepEqual(
    settingChanges({ routes: ['mx1', 'mx2'] }, { routes: ['mx2', 'mx1'] }).map(
      (r) => [changePath(r.path), r.before, r.after],
    ),
    [
      ['/routes/0', 'mx1', 'mx2'],
      ['/routes/1', 'mx2', 'mx1'],
    ],
  );
  assert.deepEqual(
    settingChanges({ rules: [{ id: 'one' }] }, { rules: [] }).map((r) =>
      changePath(r.path),
    ),
    ['/rules/0'],
  );
});
test('property names cannot alias paths or inherit prototype data', () => {
  const before = JSON.parse('{"__proto__":{"x":1},"a/b":1,"a~b":2}');
  const after = JSON.parse(
    '{"__proto__":{"x":2},"a/b":3,"a~b":4,"constructor":false}',
  );
  assert.deepEqual(
    settingChanges(before, after).map((r) => changePath(r.path)),
    ['/__proto__/x', '/a~1b', '/a~0b', '/constructor'],
  );
  assert.equal(auditDescription('constructor'), 'constructor');
});
test('large or deep subtrees collapse as complete values rather than disappearing', () => {
  let before = { leaf: 1 },
    after = { leaf: 2 };
  for (let i = 0; i < 20; i++) {
    before = { next: before };
    after = { next: after };
  }
  const deep = settingChanges(before, after);
  assert.equal(deep.length, 1);
  assert.equal(deep[0].path.length, 12);
  assert.notEqual(settingValue(deep[0].before), settingValue(deep[0].after));
  const a = {},
    b = {};
  for (let i = 0; i < 2200; i++) {
    a['k' + i] = { x: 1 };
    b['k' + i] = { x: 2 };
  }
  const large = settingChanges(a, b);
  assert.equal(large.length, 2200);
  assert.ok(large.some((r) => r.path.length === 1));
  assert.ok(
    large.every((r) => settingValue(r.before) !== settingValue(r.after)),
  );
});
test('only recorded configuration revisions produce revision links, never activation sequences or arbitrary references', () => {
  assert.equal(auditRevision('configuration', '25'), 25);
  assert.equal(auditRevision('configuration', '0'), 0);
  for (const action of [
    'configuration_staged',
    'configuration_aborted',
    'provider_key',
    'account',
  ])
    assert.equal(auditRevision(action, '25'), null);
  for (const id of ['25abc', '-1', '1.5', '1e3', '9007199254740992'])
    assert.equal(auditRevision('configuration', id), null);
  assert.match(auditDescription('configuration'), /recorded/);
  assert.match(auditDescription('configuration_staged'), /proposal staged/);
});

test('shared configuration sections retain a draft, while wizard exits and unrelated workspaces remain guarded', () => {
  for (const from of ['domains', 'gateways', 'filters', 'server']) {
    for (const to of ['domains', 'gateways', 'filters', 'server']) {
      assert.equal(keepsConfigurationDraft(from, to, false), true);
      assert.equal(keepsConfigurationDraft(from, to, true), false);
    }
    for (const to of [
      'messages',
      'users',
      'cluster',
      'preferences',
      'quality',
      'account',
    ])
      assert.equal(keepsConfigurationDraft(from, to, false), false);
  }
  assert.equal(keepsConfigurationDraft('preferences', 'filters', false), false);
});
