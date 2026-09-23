import assert from 'node:assert/strict';
import test from 'node:test';
import {
  activationLabel,
  savesBlocked,
  saveNotice,
} from '../app/activation.ts';

const prepared = {
  coordinated: true,
  phase: 'preparing',
  pending: true,
  smtp_ready: false,
  installed_revision: 4,
  committed_revision: 4,
  epoch: { sequence: 2, revision: 5 },
  incident: null,
};
test('staged saves never promise applied settings', () => {
  assert.match(
    saveNotice({ revision: 5, staged: true }),
    /submitted.*activation/,
  );
  assert.doesNotMatch(saveNotice({ revision: 5, staged: true }), /applied/);
  assert.match(
    saveNotice({ revision: 5, staged: false }),
    /applied to future messages/,
  );
});
test('installed and committed are not released or SMTP-ready', () => {
  assert.match(activationLabel(prepared), /Preparing/);
  assert.match(
    activationLabel({
      ...prepared,
      phase: 'committed',
      installed_revision: 5,
      committed_revision: 5,
    }),
    /waiting/,
  );
  assert.match(activationLabel({ ...prepared, phase: 'released' }), /resuming/);
  assert.match(
    activationLabel({
      ...prepared,
      phase: 'released',
      smtp_ready: true,
      pending: false,
    }),
    /local SMTP ready/,
  );
  assert.doesNotMatch(
    activationLabel({ ...prepared, phase: 'released', smtp_ready: true }),
    /all.*ready/i,
  );
});
test('missing or stale activation status prevents an apparently safe save', () => {
  assert.equal(savesBlocked(null, ''), true);
  assert.equal(savesBlocked(prepared, ''), true);
  const released = {
    ...prepared,
    phase: 'released',
    pending: false,
    smtp_ready: true,
  };
  assert.equal(savesBlocked(released, 'Network unavailable'), true);
  assert.equal(savesBlocked(released, ''), false);
  assert.equal(savesBlocked({ ...released, coordinated: false }, ''), false);
});
test('failure and cancellation do not masquerade as successful application', () => {
  assert.match(
    activationLabel({
      ...prepared,
      incident: { code: 'activation_step_failed' },
    }),
    /attention/,
  );
  assert.match(activationLabel({ ...prepared, phase: 'aborted' }), /Restoring/);
  assert.match(
    activationLabel({ ...prepared, phase: 'aborted', smtp_ready: true }),
    /cancelled/,
  );
});

// Render the actual component and design-system button, with no browser effects
// or mocked authorization. API authorization is exercised by Rust network tests.
const { readFile } = await import('node:fs/promises');
const { createElement } = await import('react');
const { renderToStaticMarkup } = await import('react-dom/server');
const { default: ts } = await import('typescript');
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
const utilsURL = await moduleURL('../lib/utils.ts');
const buttonURL = await moduleURL('../components/ui/button.tsx', {
  '@/lib/utils': utilsURL,
});
const { ActivationPanel } = await import(
  await moduleURL('../app/activation-view.tsx', {
    '@/components/ui/button': buttonURL,
    './client': new URL('../app/client.ts', import.meta.url).href,
    './activation': new URL('../app/activation.ts', import.meta.url).href,
  })
);
function render(view, administrator = false, error = '') {
  return renderToStaticMarkup(
    createElement(ActivationPanel, {
      user: { username: 'alice', admin: administrator, csrf: 'fixture' },
      administrator,
      state: { view, error, refresh: async () => {} },
    }),
  );
}
test('actual admin panel distinguishes installation from readiness and exposes available recovery only', () => {
  const html = render(
    {
      ...prepared,
      phase: 'committed',
      installed_revision: 5,
      committed_revision: 5,
      participants: { mx1: 'applied', mx2: 'prepared' },
      recoverable: true,
      abortable: false,
    },
    true,
  );
  assert.match(html, /Temporarily deferred/);
  assert.match(html, /Installed · acknowledged/);
  assert.match(html, /Prepared · not installed yet/);
  assert.match(html, /Restore previous policy/);
  assert.doesNotMatch(html, /Cancel staged change/);
});
test('personal panel does not render topology or recovery controls and escapes scope names', () => {
  const html = render({
    ...prepared,
    participants: { 'private-mx': 'applied' },
    abortable: true,
    recoverable: true,
    personal_change: {
      scope: '<script>@example.test',
      revision: 5,
      phase: 'preparing',
    },
  });
  assert.match(html, /Your change for/);
  assert.match(html, /&lt;script&gt;/);
  assert.doesNotMatch(
    html,
    /private-mx|Cancel staged|Restore previous|<script>/,
  );
});
test('unknown incident content never becomes a provider text disclosure', () => {
  const html = render(
    { ...prepared, incident: { at: 1700000000, code: 'secret-provider-text' } },
    true,
  );
  assert.match(html, /Activation needs attention/);
  assert.match(html, /server logs/);
  assert.doesNotMatch(html, /secret-provider-text/);
  const revoked = render(
    { ...prepared, incident: { at: 1700000000, code: 'approval_changed' } },
    true,
  );
  assert.match(revoked, /approving account or its permissions changed/);
});
