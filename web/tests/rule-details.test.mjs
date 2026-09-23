import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import ts from 'typescript';

const source = await readFile(new URL('../app/rule-details.tsx', import.meta.url), 'utf8');
let js = ts.transpileModule(source, { compilerOptions: {
  jsx: ts.JsxEmit.ReactJSX, module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022,
} }).outputText.replaceAll('"react/jsx-runtime"', JSON.stringify(import.meta.resolve('react/jsx-runtime')));
for (const name of ['diagnostics-formatters', 'scoring-format']) {
  js = js.replaceAll(`'./${name}'`, JSON.stringify(new URL(`../app/${name}.ts`, import.meta.url).href));
}
const { RuleDetails } = await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`);
const render = props => renderToStaticMarkup(createElement(RuleDetails, props));
const reason = (id, weight) => ({ id, weight, detail: 'Synthetic finding' });

test('main rule list agrees with retained accounting and counts repeated signals once', () => {
  const html = render({ reasons: [reason('spf_fail', 1), reason('dmarc_fail', 2), reason('urgency', .5), reason('urgency', .5)], scoring: {
    contributions: [
      { id: 'spf_fail', retained: 0, adjustment: 'subsumed_evidence', subsumed_by: 'dmarc_fail' },
      { id: 'dmarc_fail', retained: 2, adjustment: 'none' },
      { id: 'urgency', retained: .5, adjustment: 'duplicate' },
    ],
  } });
  assert.match(html, /Already included in the composite finding/);
  assert.match(html, /Included in <code>dmarc_fail<\/code>/);
  assert.doesNotMatch(html, /<strong>\+1<\/strong>/);
  assert.equal((html.match(/<strong>\+0.5<\/strong>/g) ?? []).length, 1);
  assert.equal((html.match(/<strong>0<\/strong>/g) ?? []).length, 2);
  assert.match(html, /Repeated occurrence · counted once/);
});

test('missing ledgers label weights as proposed and invalid retained weights are never zero', () => {
  const legacy = render({ reasons: [reason('spf_fail', 1)] });
  assert.match(legacy, /proposed log-odds/);
  assert.doesNotMatch(legacy, /Increases risk in the recorded calculation/);
  const invalid = render({ reasons: [reason('urgency', .5)], scoring: {
    contributions: [{ id: 'urgency', retained: null, adjustment: 'conflicting_weights' }],
  } });
  assert.match(invalid, /Conflicting weights/);
  assert.match(invalid, /<strong>Not recorded<\/strong>/);
  assert.doesNotMatch(invalid, /no numerical effect|<strong>0<\/strong>/);
});

test('model summaries and malware priority stay separate from retained rule weights', () => {
  const html = render({ reasons: [reason('model_contribution', 3), reason('malware_priority', 100), {
    ...reason('spf_fail', 1), detail: '<script>private</script>',
  }], scoring: { contributions: [{ id: 'spf_fail', retained: 0, adjustment: 'unavailable_evidence' }] } });
  assert.match(html, /model summary/);
  assert.match(html, /not an additional rule/);
  assert.match(html, /Antivirus priority/);
  assert.match(html, /Excluded — no usable supporting result/);
  assert.doesNotMatch(html, /<strong>\+100<\/strong>|<script>/);
  assert.match(html, /&lt;script&gt;/);
});
