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
const button = await moduleURL('../components/ui/button.tsx', {
  '@/lib/utils': await moduleURL('../lib/utils.ts'),
});

const { IdentityEvidence } = await import(
  await moduleURL('../app/identity-evidence.tsx')
);
const { ConfirmDialog } = await import(
  await moduleURL('../app/console-ui.tsx', { '@/components/ui/button': button })
);
const report = {
  observation_only: true,
  authenticated_sender: false,
  findings: [],
};
const render = (value) =>
  renderToStaticMarkup(createElement(IdentityEvidence, { report: value }));
test('missing findings never claim a clean sender or completed identity coverage', () => {
  const html = render(report);
  assert.match(html, /No identity finding recorded/);
  assert.match(html, /does not prove that every identity check ran/);
  assert.doesNotMatch(html, /Sender verified|Identity verified/);
});
test('domain authentication is kept distinct from person identity and the verdict', () => {
  const html = render({
    ...report,
    authenticated_sender: true,
    findings: [
      {
        id: 'protected_display_name',
        family: 'identity',
        detail: 'A familiar name',
        sources: ['headers'],
      },
    ],
  });
  assert.match(html, /Familiar name, unexpected domain/);
  assert.match(html, /DMARC alignment confirmed/);
  assert.match(html, /not the person/);
  assert.match(html, /Observation only/);
});
test('untrusted findings are escaped, and other signal families are not duplicated', () => {
  const html = render({
    ...report,
    findings: [
      {
        id: '<img>',
        family: 'identity',
        detail: '<ScRiPt>bad</ScRiPt>',
        sources: ['<svg>'],
      },
      {
        id: 'link',
        family: 'link_structure',
        detail: 'other family',
        sources: [],
      },
    ],
  });
  assert.match(html, /&lt;script&gt;/i);
  assert.doesNotMatch(html, /<script\b|<img\b|other family/i);
});
test('a non-observation historical report is not relabelled observation-only', () => {
  const html = render({ ...report, observation_only: false });
  assert.match(html, /See recorded decision/);
  assert.doesNotMatch(html, /Observation only/);
});
test('invalid import can disable confirmation without trapping cancellation', () => {
  const html = renderToStaticMarkup(
    createElement(
      ConfirmDialog,
      {
        title: 'Import',
        confirmLabel: 'Add to draft',
        busy: false,
        confirmDisabled: true,
        onCancel: () => {},
        onConfirm: () => {},
      },
      'Invalid rows',
    ),
  );
  assert.match(html, /<button[^>]*class="cancel-action"[^>]*>Cancel/);
  assert.doesNotMatch(html, /<button[^>]*class="cancel-action"[^>]*disabled/);
  assert.match(html, /disabled/);
  assert.doesNotMatch(html, /Processing/);
});

const { DirectoryIdentityEvidence } = await import(
  await moduleURL('../app/identity-evidence.tsx')
);
const directory = {
  catalog_sha256: 'a'.repeat(64),
  relationships_available: false,
  sensitive_requests_available: false,
  observation: {
    protocol: 'identity-detection-1',
    status: 'complete',
    observation_only: true,
    fresh_sources: 1,
    applicable_sources: 1,
    authentication: 'unavailable',
    directory_address_match: false,
    ambiguous_identity: false,
    signals: [],
    corroborated: false,
  },
};
const renderDirectory = (value) =>
  renderToStaticMarkup(
    createElement(DirectoryIdentityEvidence, { report: value }),
  );
test('directory completion does not imply a verified person or a completed contact graph', () => {
  const html = renderDirectory(directory);
  assert.match(html, /Directory checks completed/);
  assert.match(html, /human-confirmed relationship baseline was unavailable/);
  assert.match(html, /Sensitive-request analysis was unavailable/);
  assert.match(html, /does not verify the sender/);
  assert.match(html, /do not independently decide the verdict/);
  assert.match(html, /Not established by trusted SMTP evidence/);
});
test('missing, stale and ambiguous directory evidence is not presented as safe', () => {
  for (const status of [
    'stale',
    'not_configured',
    'unavailable',
    'limited',
    'future_status',
  ]) {
    const html = renderDirectory({
      ...directory,
      observation: {
        ...directory.observation,
        status,
        ambiguous_identity: true,
      },
    });
    assert.doesNotMatch(html, /Directory checks completed/);
    assert.match(html, /No unique person or group was established/);
  }
});
test('directory addresses and provenance remain observations, and identifiers are escaped', () => {
  const html = renderDirectory({
    ...directory,
    catalog_sha256: '<script>unsafe</script>',
    observation: {
      ...directory.observation,
      authentication: 'aligned',
      directory_address_match: true,
      signals: ['protected_name_mismatch', '<img src=x>'],
    },
  });
  assert.match(html, /Protected name, different address/);
  assert.match(html, /does not prove who wrote the message/);
  assert.match(html, /DMARC alignment confirmed/);
  assert.match(html, /&lt;script&gt;/i);
  assert.doesNotMatch(html, /<script\b|<img\b/i);
});

const input = await moduleURL('../components/ui/input.tsx', {
  '@/lib/utils': await moduleURL('../lib/utils.ts'),
});
const { DirectoryReview } = await import(
  await moduleURL('../app/directory-settings.tsx', {
    './directory-sync': await moduleURL('../app/directory-sync.tsx', {
      './directory': await moduleURL('../app/directory.ts'),
      './client': await moduleURL('../app/client.ts'),
      './directory-connections': await moduleURL(
        '../app/directory-connections.tsx',
      ),
      './console-ui': await moduleURL('../app/console-ui.tsx', {
        '@/components/ui/button': button,
      }),
    }),
    '@/components/ui/button': button,
    '@/components/ui/input': input,
    './client': await moduleURL('../app/client.ts'),
    './console-ui': await moduleURL('../app/console-ui.tsx', {
      '@/components/ui/button': button,
    }),
    './directory': await moduleURL('../app/directory.ts'),
  })
);
const prepared = {
  active: false,
  revision: 25,
  selection: { sha256: 'b'.repeat(64), reviewed_from: 'a'.repeat(64) },
  review: {
    operation: 'remove',
    source_id: 'example',
    source_label: '<script>Example</script>',
    people: { added: 0, changed: 1, removed: 3 },
    groups: { added: 0, changed: 0, removed: 1 },
    membership_changes: 4,
    delegation_changes: 2,
    removed_or_disabled: 4,
    protected_identity_changes: 2,
    source_configuration_changed: true,
    requires_attention: true,
    before: null,
    after: null,
  },
};
test('directory review escapes source data and distinguishes preparation from activation', () => {
  const html = renderToStaticMarkup(
    createElement(DirectoryReview, { prepared }),
  );
  assert.ok(html.includes('&lt;script&gt;Example&lt;/script&gt;'));
  assert.doesNotMatch(html, /<script\b/i);
  assert.match(html, /No change is active yet/);
  assert.match(html, /Active identities removed or disabled/);
  assert.match(html, /Protected identity changes/);
  assert.match(html, /check source coverage, intended removals/i);
});
