import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import ts from 'typescript';

const source = await readFile(
  new URL('../app/release-readiness-view.tsx', import.meta.url),
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
  .outputText.replaceAll(
    '"react/jsx-runtime"',
    JSON.stringify(import.meta.resolve('react/jsx-runtime')),
  );
const { ReleaseReadinessView, ReadinessExclusions } = await import(
  `data:text/javascript;base64,${Buffer.from(js).toString('base64')}`
);
const render = (props) =>
  renderToStaticMarkup(createElement(ReleaseReadinessView, props));
const key = 'a'.repeat(64);
const report = {
  schema: 'noisefence-release-readiness-2',
  current_cohort: key,
  cohorts: {
    [key]: {
      messages: 12000,
      usable: 23,
      wanted: 10000,
      unwanted: 2000,
      uncertain: 0,
      unlabelled: 0,
      usable_wanted: 17,
      usable_unwanted: 6,
      usable_uncertain: 0,
      usable_unlabelled: 0,
      exclusions: { incomplete_extraction: 11977 },
    },
  },
  minimum_wanted_test_messages: 10000,
  minimum_unwanted_test_messages: 2000,
  qualification_required: true,
  blockers: [
    'insufficient_wanted_labels',
    'insufficient_unwanted_labels',
    'independent_evaluation_required',
  ],
};

test('actual readiness view separates human labels from usable intersections without implying qualification', () => {
  const html = render({ report });
  assert.match(
    html,
    /<th scope="row">Wanted<\/th><td>10,000<\/td><td>17<\/td>/,
  );
  assert.match(
    html,
    /<th scope="row">Unwanted<\/th><td>2,000<\/td><td>6<\/td>/,
  );
  assert.match(html, /23 usable SMTP observations/);
  assert.match(html, /Content extraction incomplete.*11,977/);
  assert.match(html, /Independent qualification required/);
  assert.match(html, /have not been deduplicated by campaign/);
  assert.match(html, /do not establish membership in an independent test set/);
  assert.match(html, /Missing evidence does not mean legitimate mail/);
  assert.doesNotMatch(html, /Ready to activate|Qualified|100%/);
});

test('older contracts and unknown installed identity do not invent usable labels or a zero population', () => {
  const old = render({
    report: { ...report, schema: 'noisefence-release-readiness-1' },
  });
  assert.match(old, /does not provide compatible/);
  assert.doesNotMatch(old, /<table>|10,000|17|0 recorded messages/);
  const unknown = render({ report: { ...report, current_cohort: '' } });
  assert.match(unknown, /counts cannot be determined/);
  assert.doesNotMatch(unknown, /<table>|0 recorded messages/);
  const empty = render({ report: { ...report, cohorts: {} } });
  assert.match(empty, /0 recorded messages/);
  assert.match(empty, /Independent qualification required/);
});

test('loading and errors hide previous counts and never display an unavailable count as zero', () => {
  assert.match(render({ report: null }), /Loading dataset readiness/);
  const error = render({ report, error: '<b>Request failed</b>' });
  assert.match(error, /role="alert"/);
  assert.match(error, /&lt;b&gt;Request failed&lt;\/b&gt;/);
  assert.doesNotMatch(error, /<table>|12,000 recorded/);
  const absent = render({
    report: {
      ...report,
      cohorts: { [key]: { ...report.cohorts[key], usable_wanted: undefined } },
    },
  });
  assert.match(
    absent,
    /<th scope="row">Wanted<\/th><td>10,000<\/td><td>Not recorded<\/td>/,
  );
});

test('sample and global exclusion details share fixed labels and do not echo unknown diagnostic keys', () => {
  const html = renderToStaticMarkup(
    createElement(ReadinessExclusions, {
      exclusions: {
        unsupported_protocol: 2,
        non_smtp_observation: 1,
        invalid_features: 3,
        '<script>PRIVATE KEY</script>': 1,
        constructor: 1,
      },
    }),
  );
  assert.match(html, /Incompatible feature protocol.*2/);
  assert.match(html, /Not an original SMTP observation.*1/);
  assert.match(html, /Feature vector missing or invalid.*3/);
  assert.match(html, /Other unavailable observations/);
  assert.doesNotMatch(html, /PRIVATE|<script>|constructor/);
  assert.equal(
    renderToStaticMarkup(createElement(ReadinessExclusions, {})),
    '',
  );
});
