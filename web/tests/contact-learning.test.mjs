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
const button = await moduleURL('../components/ui/button.tsx', {
  '@/lib/utils': await moduleURL('../lib/utils.ts'),
});
const ui = await moduleURL('../app/console-ui.tsx', {
  '@/components/ui/button': button,
});
const {
  ContactLearningEvidence,
  ContactLearningSettingsEditor,
  defaultContactLearning,
  contactLearningError,
} = await import(
  await moduleURL('../app/contact-learning.tsx', { './console-ui': ui })
);
const report = {
  status: 'regular',
  observation_only: true,
  regular: true,
  campaigns: 6,
  observed_days: 5,
  last_seen_at: null,
  retention_days: 30,
  minimum_campaigns: 5,
  minimum_days: 3,
  blocked_by_feedback: false,
  content_comparison_available: true,
  changes: [],
};
const render = (value) =>
  renderToStaticMarkup(
    createElement(ContactLearningEvidence, { report: value }),
  );
test('recurrence is presented separately from trust, score and training', () => {
  const html = render(report);
  assert.match(html, /Recurring address in authenticated history/);
  assert.match(html, /6 distinct campaigns on 5 days/);
  assert.match(html, /Frequency is not identity verification/);
  assert.match(html, /can be compromised/);
  assert.doesNotMatch(html, /Trusted sender|Verified identity|safe sender/i);
  const settings = renderToStaticMarkup(
    createElement(ContactLearningSettingsEditor, {
      disabled: false,
      onChange() {},
    }),
  );
  assert.match(
    settings,
    /never bypasses phishing checks, changes a verdict or creates training labels/,
  );
  assert.doesNotMatch(settings, /checked=""/);
});
test('missing, partial and ineligible observations never manufacture novelty', () => {
  for (const status of [
    'limited',
    'unavailable',
    'ineligible',
    'future_status',
  ]) {
    const html = render({
      ...report,
      status,
      regular: false,
      campaigns: 500,
      observed_days: 30,
      content_comparison_available: false,
    });
    assert.doesNotMatch(html, /500 distinct campaigns/);
    assert.doesNotMatch(html, /No change was observed/);
    assert.match(html, /unavailable|incomplete|not eligible/);
  }
});
test('changed patterns and human veto remain visible without promoting model labels', () => {
  const html = render({
    ...report,
    changes: [
      'reply_destination',
      'sensitive_request',
      '<script>unsafe</script>',
    ],
  });
  assert.match(html, /Reply destination differs/);
  assert.match(html, /Sensitive request is new/);
  assert.doesNotMatch(html, /<script\b/i);
  assert.match(
    render({
      ...report,
      status: 'human_rejected',
      regular: false,
      blocked_by_feedback: true,
    }),
    /Frequent delivery does not override/,
  );
});
test('policy bounds reject unsafe or impossible maturity and window settings', () => {
  assert.equal(contactLearningError(defaultContactLearning), null);
  assert.equal(contactLearningError(null), null);
  for (const patch of [
    { minimum_campaigns: 1 },
    { minimum_days: 1 },
    { retention_days: 31 },
    { retention_days: 7, minimum_campaigns: 20 },
    { minimum_days: NaN },
    { learn_since: -1 },
    { retention_days: 7.5 },
  ])
    assert.ok(contactLearningError({ ...defaultContactLearning, ...patch }));
  assert.equal(
    contactLearningError({
      ...defaultContactLearning,
      retention_days: 7,
      minimum_campaigns: 14,
      minimum_days: 7,
    }),
    null,
  );
});

test('a forged recurring address is compared without being learned or declared authenticated', () => {
  const html = render({
    ...report,
    learning_eligible: false,
    dkim_alignment: 'not_verified',
    changes: ['dkim_alignment', 'reply_destination'],
  });
  assert.match(html, /excluded from automatic learning/);
  assert.match(html, /claimed address, not the identity/);
  assert.match(html, /DKIM alignment differs/);
  assert.doesNotMatch(html, /Recurring authenticated contact/);
  const missing = render({
    ...report,
    learning_eligible: false,
    dkim_alignment: 'unavailable',
  });
  assert.match(
    missing,
    /Missing authentication is not recorded as a failed check/,
  );
  assert.doesNotMatch(missing, /does not have verified DKIM alignment/);
});
