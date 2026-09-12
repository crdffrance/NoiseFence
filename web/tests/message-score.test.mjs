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
    assert.equal(shown.label, 'Score indicatif');
    assert.match(
      shown.detail,
      resolution === 'ambiguous' ? /incertain/ : /contredisent/,
    );
    assert.equal(classification(mail, 95).label, 'À vérifier');
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
  assert.match(shown.detail, /Contrôles incomplets : analyse LLM/);
  assert.equal(classification(mail, 95).label, 'Analyse incomplète');
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
  assert.match(shown.detail, /contenu partiellement exploité/);
  assert.match(shown.detail, /délai global/);
  assert.equal(shown.detail.match(/OCR/g).length, 1);
  assert.doesNotMatch(shown.detail, /script|private/);
  assert.equal(shown.value, 99.4);
});

test('lack of corroboration keeps the existing decision score and review status', () => {
  const mail = { ...base, decision: decision('legacy', 'undetermined', 98.2) };
  assert.equal(scorePresentation(mail).value, 98.2);
  assert.match(scorePresentation(mail).detail, /confirmation est insuffisante/);
  assert.equal(classification(mail, 95).label, 'À vérifier');
});

test('the antivirus missing-control explanation uses its actual state, not a generic signature reason', () => {
  const mail = {
    ...base,
    complete: false,
    reasons: [{ id: 'antivirus' }, { id: 'constructor' }, { id: '__proto__' }],
  };
  assert.match(
    scorePresentation({ ...mail, antivirus: { status: 'unscannable' } }).detail,
    /Contrôles incomplets : antivirus\./,
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
  assert.equal(shown.label, 'Score de fusion');
  const fallback = scorePresentation({
    ...base,
    decision: decision('fusion', 'undetermined', null),
  });
  assert.equal(fallback.value, 99.4);
  assert.equal(fallback.model, 'content-v1');
  assert.equal(fallback.label, 'Score indicatif');
  assert.doesNotMatch(fallback.detail, /calibrée/);
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
  assert.equal(shown.label, 'Valeur interne');
  assert.match(shown.detail, /ne correspond pas à l’analyse/);
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
  './brand': await compileComponent('brand'),
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
  assert.match(row, /aria-label="Score partiel sur 100"/);
  assert.match(row, /value="72\.35"/);
  assert.match(row, /Score partiel/);
  const detail = renderToStaticMarkup(
    createElement(MessageScoreDetails, { mail }),
  );
  assert.match(detail, />72\.3<span>\/ 100/);
  assert.match(detail, /analyse LLM/);
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
  assert.match(rendered, /Score indicatif/);
  assert.doesNotMatch(rendered, /Indice indisponible|>—</);
});
