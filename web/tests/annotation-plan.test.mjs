import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import ts from 'typescript';
const source = await readFile(
  new URL('../app/annotation-plan.tsx', import.meta.url),
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
const { AnnotationNextSteps } = await import(
  `data:text/javascript;base64,${Buffer.from(js).toString('base64')}`
);
const render = (value) =>
  renderToStaticMarkup(createElement(AnnotationNextSteps, { value }));
const row = {
  target: 'risk',
  partition: 'train',
  ready: false,
  minimum_additional_labelled_campaigns: 7,
  unlabelled_or_uncertain_campaigns: 3,
  minimum_new_campaigns_by_count: 4,
  missing_classes: ['spam'],
};
const plan = {
  schema: 'noisefence-annotation-plan-1',
  scope: 'development_only',
  may_activate: false,
  risk_ready: false,
  mail_kind_ready: false,
  risk_requires_mail_kind: false,
  partitions: [row],
};

test('collection guidance cannot turn missing labels into a quota or guarantee', () => {
  const html = render(plan);
  assert.match(html, /At least 4 more campaigns by count/);
  assert.match(html, /Review remaining unlabelled or uncertain campaigns/);
  assert.match(html, /Mail-type labels do not block risk fitting/);
  assert.match(html, /cannot guarantee the missing classes/);
  assert.match(html, /Do not assign a label to fill a quota/);
  assert.match(html, /New arrivals cannot fill an old fixed partition/);
});
test('risk readiness remains independent of mail type and production activation', () => {
  const html = render({ ...plan, risk_ready: true, partitions: [] });
  assert.match(html, /Risk fitting is ready for development/);
  assert.match(html, /Independent qualification is still required/);
  assert.match(html, /Mail-type fitting: not ready yet/);
  assert.match(html, /No model or delivery policy is activated/);
});
test('missing chronology does not show fabricated annotation counts', () => {
  const html = render({
    ...plan,
    partitions: [
      {
        ...row,
        unlabelled_or_uncertain_campaigns: null,
        minimum_new_campaigns_by_count: null,
      },
    ],
  });
  assert.match(html, /Not measurable/);
  assert.match(html, /Collect a wider chronological window/);
  assert.doesNotMatch(html, /At least 0/);
});
test('unknown or activation-authorizing plans are not displayed as valid', () => {
  for (const change of [
    { schema: 'future' },
    { scope: 'holdout' },
    { may_activate: true },
    { risk_requires_mail_kind: true },
  ]) {
    assert.match(render({ ...plan, ...change }), /not supported/);
    assert.doesNotMatch(render({ ...plan, ...change }), /<table/);
  }
});
