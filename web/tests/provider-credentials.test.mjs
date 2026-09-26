import assert from 'node:assert/strict';
import test from 'node:test';
import {
  keySaveNotice,
  providerCredentialLabel,
  providerToggleDisabled,
} from '../app/provider-credentials.ts';
test('saved or replaced credentials do not imply applied settings', () => {
  assert.match(providerCredentialLabel(true), /apply settings to load/);
  assert.match(providerCredentialLabel(true, true, true), /not applied/);
  assert.match(providerCredentialLabel(true, true, false), /captured/);
  assert.equal(providerCredentialLabel(false, false, false), 'Key required');
});
test('a source file removal never prevents disabling an enabled connector', () => {
  assert.match(providerCredentialLabel(false, true, true), /not applied/);
  assert.equal(providerToggleDisabled(false, false, true), false);
  assert.equal(providerToggleDisabled(false, true, false), false);
  assert.equal(providerToggleDisabled(false, false, false), true);
});

test('staged credential saves are never reported as an applied reload', () => {
  assert.match(
    keySaveNotice({ staged: true, active: true }),
    /not applied until every MX/,
  );
  assert.match(keySaveNotice({ active: true }), /future analyses/);
  assert.match(keySaveNotice({ active: false }), /Apply settings/);
});
