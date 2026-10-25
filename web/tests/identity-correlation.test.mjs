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
      (_, _quote, specifier) =>
        `from ${JSON.stringify(bindings[specifier] ?? import.meta.resolve(specifier))}`,
    );
  return `data:text/javascript;base64,${Buffer.from(js).toString('base64')}`;
}

const {
  IdentityPolicyEditor,
  identityPolicyError,
  IdentityCorrelationEvidence,
} = await import(await moduleURL('../app/identity-correlation.tsx'));
const report = {
  protocol: 'identity-correlation-1',
  policy_sha256: 'a'.repeat(64),
  mode: 'observation',
  status: 'complete',
  content_available: true,
  recurrence_available: true,
  authentication: 'aligned',
  signals: ['recurring_reply_changed', 'sensitive_request'],
  corroborated: true,
  proposed_weight: 1,
  applied_weight: 0,
};
const render = (r, retained) =>
  renderToStaticMarkup(
    createElement(IdentityCorrelationEvidence, { report: r, retained }),
  );
test('identity observation proposals are not displayed as applied weights or spam verdicts', () => {
  const html = render(report);
  assert.match(html, /Observation only/);
  assert.match(html, /No score change/);
  assert.match(html, /proposed contribution was 1.00/);
  assert.match(html, /does not prove identity/);
  assert.doesNotMatch(
    html,
    /Spam probability|Trusted sender|automatically classified as spam/i,
  );
});
test('identity panel shows the deduplicated ledger rather than proposed weight', () => {
  const html = render({ ...report, mode: 'contribute', applied_weight: 1 }, 0);
  assert.match(html, /retained 0.00 log-odds/);
  assert.doesNotMatch(html, /retained 1.00/);
  assert.match(
    render({ ...report, mode: 'contribute' }),
    /No identity weight retained/,
  );
});
test('unavailable identity checks and hostile labels cannot imply a safe sender', () => {
  const html = render({
    ...report,
    status: 'unavailable',
    corroborated: false,
    content_available: false,
    recurrence_available: false,
    signals: ['<script>'],
  });
  assert.match(html, /Insufficient identity context/);
  assert.match(html, /Missing checks add no weight/);
  assert.doesNotMatch(html, /<script>|No corroborated change/);
});
test('identity settings default to observation, respect lockout and validate bounded inputs', () => {
  const html = renderToStaticMarkup(
    createElement(IdentityPolicyEditor, { disabled: true, onChange() {} }),
  );
  assert.match(html, /value="observation" selected/);
  assert.match(html, /fieldset disabled/);
  assert.equal(identityPolicyError(null), null);
  for (const maximum_weight of [-1, 1.1, NaN, Infinity])
    assert.ok(identityPolicyError({ mode: 'contribute', maximum_weight }));
  assert.equal(
    identityPolicyError({ mode: 'contribute', maximum_weight: 0.75 }),
    null,
  );
});
