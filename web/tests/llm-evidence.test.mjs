import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import ts from 'typescript';
const code = ts.transpileModule(
  await readFile(new URL('../app/llm-evidence.ts', import.meta.url), 'utf8'),
  {
    compilerOptions: {
      module: ts.ModuleKind.ESNext,
      target: ts.ScriptTarget.ES2022,
    },
  },
).outputText;
const { groundingSummary, responseIssueLabel } = await import(
  `data:text/javascript;base64,${Buffer.from(code).toString('base64')}`
);
test('legacy responses do not invent verified citations', () =>
  assert.equal(groundingSummary(null), null));
test('verified citations are not presented as verified decisions', () => {
  const s = groundingSummary({
    supported: true,
    accepted_citations: 2,
    issues: [],
  });
  assert.match(s.detail, /does not prove the verdict/);
});
test('unsupported and unknown claims cannot masquerade as scoring evidence', () => {
  const s = groundingSummary({
    supported: false,
    accepted_citations: 0,
    issues: [
      'ownership_not_observed',
      'ownership_not_observed',
      '<script>canary</script>',
    ],
  });
  assert.match(s.detail, /No LLM scoring weight/);
  assert.match(s.detail, /Domain ownership was not established/);
  assert.ok(!s.detail.includes('canary'));
});

test('provider response failures have fixed safe explanations', () => {
  assert.match(responseIssueLabel('output_limit'), /limit reached/);
  assert.equal(
    responseIssueLabel('<script>secret</script>'),
    'Invalid provider response',
  );
  assert.equal(responseIssueLabel(null), null);
});
