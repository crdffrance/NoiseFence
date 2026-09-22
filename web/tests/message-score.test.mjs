import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import ts from 'typescript';
import { scorePresentation, classification } from '../app/presentation.ts';

const base = {
  complete: true,
  score: 99.4,
  model: 'content-v1',
  category: 'undetermined',
  tagged: false,
  pub_tagged: false,
};
const decision = (source, outcome, score) => ({
  source,
  outcome,
  score,
  model: `${source}-v1`,
});

test('ambiguous and contradictory opinions retain the recorded score without classifying spam', () => {
  for (const resolution of ['ambiguous', 'disagreement']) {
    const mail = Object.freeze({
      ...base,
      decision: Object.freeze(decision('legacy', 'undetermined', null)),
      arbitration: { resolution },
    });
    const shown = scorePresentation(mail);
    assert.equal(shown.value, 99.4);
    assert.equal(shown.model, 'content-v1');
    assert.equal(shown.kind, 'advisory');
    assert.equal(shown.label, "Advisory risk index");
    assert.match(
      shown.detail,
      resolution === 'ambiguous' ? /uncertain/ : /disagree/,
    );
    assert.equal(classification(mail, 95).label, "Needs review");
    assert.equal(mail.decision.score, null);
    assert.equal(mail.tagged, false);
  }
});

test('an incomplete LLM check preserves numeric results and explicitly describes the missing control', () => {
  const mail = {
    ...base,
    complete: false,
    score: 72.35,
    decision: decision('legacy', 'undetermined', null),
    reasons: [{ id: 'llm_unavailable' }],
  };
  const shown = scorePresentation(mail);
  assert.equal(shown.value, 72.35);
  assert.equal(shown.kind, 'partial');
  assert.match(shown.detail, /Incomplete checks: LLM analysis/);
  assert.equal(classification(mail, 95).label, "Needs review");
});

test('limited extraction and multiple missing controls are not described as a complete content analysis', () => {
  const shown = scorePresentation({
    ...base,
    complete: false,
    evidence: { lexical_state: 'limited' },
    reasons: [
      { id: 'checks_unavailable' },
      { id: 'vision_incomplete' },
      { id: 'vision_incomplete' },
      { id: '<script>private@example.test</script>' },
    ],
  });
  assert.match(shown.detail, /limited content extraction/);
  assert.match(shown.detail, /overall deadline/);
  assert.equal(shown.detail.match(/OCR/g).length, 1);
  assert.doesNotMatch(shown.detail, /script|private/);
  assert.equal(shown.value, 99.4);
});

test('lack of corroboration keeps the existing decision score and review status', () => {
  const mail = { ...base, decision: decision('legacy', 'undetermined', 98.2) };
  assert.equal(scorePresentation(mail).value, 98.2);
  assert.match(scorePresentation(mail).detail, /Corroboration is insufficient/);
  assert.equal(classification(mail, 95).label, "Needs review");
});

test('the antivirus missing-control explanation uses its actual state, not a generic signature reason', () => {
  const mail = {
    ...base,
    complete: false,
    reasons: [{ id: 'antivirus' }, { id: undefined }, { id: {} }],
  };
  assert.match(
    scorePresentation({ ...mail, antivirus: { status: 'unscannable' } }).detail,
    /Incomplete checks: antivirus\./,
  );
  assert.doesNotMatch(
    scorePresentation({ ...mail, antivirus: { status: 'clean' } }).detail,
    /antivirus|function|Object/,
  );
});

test('fusion uses its own score and fallback uses the content model without claiming calibration', () => {
  const shown = scorePresentation({
    ...base,
    decision: decision('fusion', 'legitimate', 2.4),
  });
  assert.equal(shown.value, 2.4);
  assert.equal(shown.model, 'fusion-v1');
  assert.equal(shown.label, "Fusion estimate");
  const fallback = scorePresentation({
    ...base,
    decision: decision('fusion', 'undetermined', null),
  });
  assert.equal(fallback.value, 99.4);
  assert.equal(fallback.model, 'content-v1');
  assert.equal(fallback.label, "Advisory risk index");
  assert.doesNotMatch(fallback.detail, /calibrated/);
});

test('malware remains the classification even when the content index is low or incomplete', () => {
  for (const complete of [true, false]) {
    const mail = {
      ...base,
      score: 3.2,
      complete,
      decision: decision('antivirus', 'unwanted', null),
    };
    assert.equal(scorePresentation(mail).value, 3.2);
    assert.match(scorePresentation(mail).detail, /antivirus/);
    assert.equal(classification(mail).label, 'Malware');
    assert.equal(mail.decision.score, null);
  }
});

test('only recorded finite scores are displayed; missing or invalid results never become an invented zero', () => {
  for (const value of [
    null,
    undefined,
    NaN,
    Infinity,
    -Infinity,
    -1,
    101,
    '98',
  ]) {
    assert.equal(scorePresentation({ ...base, score: value }).value, null);
    assert.equal(
      scorePresentation({
        ...base,
        score: value,
        decision: decision('fusion', 'undetermined', value),
      }).kind,
      'unavailable',
    );
  }
  assert.equal(
    scorePresentation({ ...base, score: 0, complete: false }).value,
    0,
  );
  assert.equal(scorePresentation({ ...base, score: 100 }).value, 100);
  assert.equal(
    scorePresentation({
      ...base,
      decision: decision('fusion', 'undetermined', NaN),
    }).value,
    99.4,
  );
});

test('internal delivery notifications do not present their stored zero as an incoming scan', () => {
  const shown = scorePresentation({ ...base, score: 0, model: 'dsn' });
  assert.equal(shown.value, 0);
  assert.equal(shown.label, "Internal value");
  assert.match(shown.detail, /not an analysis/);
});

test('an advisory score describes detector uncertainty without contradicting a recipient rule', () => {
  for (const [category, label] of [
    ['spam', 'Spam'],
    ['legitimate', "Legitimate"],
    ['publicity', "Marketing"],
  ]) {
    const mail = {
      ...base,
      decision: decision('legacy', 'undetermined', null),
      delivery_classification: category,
    };
    const shown = scorePresentation(mail);
    assert.equal(shown.value, 99.4);
    assert.match(shown.detail, /engine decision is undetermined/);
    assert.doesNotMatch(shown.detail, /message remains Needs review/);
    assert.equal(classification(mail).label, label);
  }
});

async function compileComponent(name, imports = {}) {
  const source = await readFile(
    new URL(`../app/${name}.tsx`, import.meta.url),
    'utf8',
  );
  const compiled = ts
    .transpileModule(source, {
      compilerOptions: {
        jsx: ts.JsxEmit.ReactJSX,
        module: ts.ModuleKind.ESNext,
        target: ts.ScriptTarget.ES2022,
      },
    })
    .outputText.replace(
      /from ["']([^"']+)["']/g,
      (_, specifier) =>
        `from ${JSON.stringify(imports[specifier] ?? import.meta.resolve(specifier))}`,
    );
  return `data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`;
}
const components = await compileComponent('message-score', {
  './policy-trace-view': await compileComponent('policy-trace-view', {
    './policy-trace': new URL('../app/policy-trace.ts', import.meta.url).href,
  }),
  './brand': await compileComponent('brand'),
  './action-coverage': new URL('../app/action-coverage.ts', import.meta.url).href,
  './action-coverage-view': await compileComponent('action-coverage-view', {
    './action-coverage': new URL('../app/action-coverage.ts', import.meta.url).href,
  }),
  './assessment': new URL('../app/assessment.ts', import.meta.url).href,
  './presentation': new URL('../app/presentation.ts', import.meta.url).href,
});
const { MessageScore, MessageScoreDetails } = await import(components);

test('journal, mobile and detail components expose the partial number and its meaning accessibly', () => {
  const mail = {
    ...base,
    complete: false,
    score: 72.35,
    decision: decision('legacy', 'undetermined', null),
    reasons: [{ id: 'llm_unavailable' }],
  };
  const row = renderToStaticMarkup(
    createElement(MessageScore, { mail, tone: 'review' }),
  );
  assert.match(row, /aria-label="Partial risk index out of 100"/);
  assert.match(row, /value="72\.35"/);
  assert.match(row, /Partial risk index/);
  const detail = renderToStaticMarkup(
    createElement(MessageScoreDetails, { mail }),
  );
  assert.match(detail, />72\.3<span>\/ 100/);
  assert.match(detail, /LLM analysis/);
  assert.match(detail, /content-v1/);
});

test('the review component no longer renders an empty score for an ambiguous opinion', () => {
  const mail = {
    ...base,
    decision: decision('legacy', 'undetermined', null),
    arbitration: { resolution: 'ambiguous' },
  };
  const rendered = renderToStaticMarkup(createElement(MessageScore, { mail }));
  assert.match(rendered, /value="99\.4"/);
  assert.match(rendered, /Advisory risk index/);
  assert.doesNotMatch(rendered, /Risk index unavailable|>—</);
});

test('review reasons distinguish context conflicts from inconsistent LLM advice', () => {
  const mail = {...base, decision: decision('legacy','undetermined',null)};
  assert.match(scorePresentation({...mail,reasons:[{id:'llm_inconsistent'}]}).detail,/category and risk estimate are inconsistent/);
  assert.match(scorePresentation({...mail,reasons:[{id:'context_requires_review'}]}).detail,/reporting or receipt context/);
});

test('partial coverage preserves a supported threat verdict without implying enforcement', () => {
  const shown=scorePresentation({...base,complete:false,decision:decision('legacy','unwanted',null),reasons:[{id:'smtp_policy_unavailable'},{id:'observed_threat_partial'}]});
  assert.equal(shown.kind,'partial');
  assert.match(shown.detail,/Corroborated phishing evidence/);
  assert.match(shown.detail,/recorded action policy/);
});

test('the actual detail component displays missing action evidence without hiding the score', () => {
  const assessment = {version:1,category:'spam',complete:false,score:{value:99.4,kind:'partial',model:'fixture',source:'raw'},
    decision:decision('legacy','unwanted',99.4),incomplete_reasons:['smtp_policy_unavailable'],content_threshold:95,
    action:{requested:'tag',effective:'deliver',reason:'subject_rewrite_unavailable',coverage:{version:'action-coverage-1',partial_actions:true,
      basis:'score_threshold',required:['usable_content','subject_rewrite'],missing:['subject_rewrite']}}};
  const mail = {...base,recipient_decision:{version:1,classification:'spam',coverage:'partial',policy_sha256:'a'.repeat(64),assessment}};
  const html = renderToStaticMarkup(createElement(MessageScoreDetails,{mail}));
  assert.match(html,/99\.4/);
  assert.match(html,/cannot be rewritten safely/);
  assert.match(html,/Configured score threshold/);
  assert.match(html,/<strong>Met<\/strong> · Content extraction completed/);
  assert.match(html,/<strong>Missing<\/strong> · Subject renderer ready/);
});

test('the receipt detail renders inherited threshold ownership and escaped rule names', () => {
  const assessment={version:1,category:'spam',complete:true,score:{value:96,kind:'content',model:'fixture',source:'raw'},
    decision:decision('legacy','unwanted',96),incomplete_reasons:[],content_threshold:95,action:null};
  const trace={version:'recipient-policy-trace-1',ordering:'scoped',threshold_profile:'domain',threshold_locked:false,
    profiles:[{id:'mailbox',name:'Personal actions',scope:'alice@example.test',origin:'personal',threshold:null,selected:true},
      {id:'domain',name:'Domain threshold',scope:'*@example.test',origin:'administrator',threshold:95,selected:false}],
    rules:[{id:'one',name:'<script>rule</script>',scope:'*',origin:'administrator',priority:0,outcome:'missing_facts',unavailable:['body'],
      category_before:'spam',category_after:'spam',action_before:'deliver',action_after:'deliver',stop:false}],
    stopped_by:null,category_rule:null,action_rule:null,malware_override:false};
  const mail={...base,recipient_decision:{version:1,classification:'spam',coverage:'complete',policy_sha256:'b'.repeat(64),assessment,policy_trace:trace}};
  const html=renderToStaticMarkup(createElement(MessageScoreDetails,{mail}));
  assert.match(html,/Policy inheritance and rule decisions/);
  assert.match(html,/Threshold source: <strong>Domain threshold \(\*@example.test\)<\/strong>/);
  assert.match(html,/Selected actions/); assert.match(html,/Missing facts/); assert.match(html,/unavailable: body/);
  assert.match(html,/&lt;script&gt;rule&lt;\/script&gt;/); assert.doesNotMatch(html,/<script>/);
});
