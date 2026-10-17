import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';
const source = await readFile(
  new URL('../app/policy-draft-changes.tsx', import.meta.url),
  'utf8',
);
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
    (_, q, name) => `from ${JSON.stringify(import.meta.resolve(name))}`,
  );
const { policyChanges } = await import(
  `data:text/javascript;base64,${Buffer.from(js).toString('base64')}`
);
const base = {
  ordering: 'scoped',
  profiles: [{ id: 'careful', name: 'Careful', threshold: 95 }],
  bindings: [{ scope: '*@example.test', profile: 'careful' }],
  rules: [{ id: 'invoice', name: 'Invoice', priority: 1 }],
};
test('changed settings distinguish added, removed and changed identities', () => {
  const draft = {
    ...base,
    profiles: [{ ...base.profiles[0], threshold: 98 }],
    bindings: [],
    rules: [{ id: 'news', name: 'Newsletter', priority: 2 }],
  };
  assert.deepEqual(policyChanges(base, draft), [
    {
      section: 'profiles',
      key: 'careful',
      change: 'Changed',
      fields: ['threshold'],
    },
    {
      section: 'bindings',
      key: '*@example.test',
      change: 'Removed',
      fields: [],
    },
    { section: 'rules', key: 'invoice', change: 'Removed', fields: [] },
    { section: 'rules', key: 'news', change: 'Added', fields: [] },
  ]);
});
test('serialization key order does not fabricate a changed profile', () => {
  const draft = {
    ...base,
    profiles: [{ threshold: 95, name: 'Careful', id: 'careful' }],
  };
  assert.deepEqual(policyChanges(base, draft), []);
});
test('legacy inheritance and empty policy are compared explicitly', () => {
  assert.deepEqual(
    policyChanges(null, { profiles: [], bindings: [], rules: [] }),
    [],
  );
  assert.deepEqual(
    policyChanges(null, {
      ordering: 'scoped',
      profiles: [],
      bindings: [],
      rules: [],
    }),
    [
      {
        section: 'Ordering',
        key: 'policy',
        change: 'legacy_priority → scoped',
        fields: [],
      },
    ],
  );
});
