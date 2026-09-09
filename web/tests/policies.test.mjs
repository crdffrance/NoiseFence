import assert from 'node:assert/strict';
import test from 'node:test';
import { deliveryPolicy, restoreDefaults } from '../app/policies.ts';

test('an old revision restores the server legacy actions, not the active quarantine policy', () => {
  const active = {
    spam: 'quarantine',
    malware: 'quarantine',
    publicity: 'quarantine',
    quarantine_days: 7,
  };
  const old = { filters: { mode: 'observe' }, mailing: { tag_subject: false } };
  const restored = restoreDefaults(old);
  assert.deepEqual(deliveryPolicy(restored), {
    spam: 'tag',
    malware: 'tag',
    publicity: 'deliver',
    quarantine_days: 14,
  });
  assert.notDeepEqual(deliveryPolicy(restored), active);
  assert.equal(restored.actions, null);
  assert.deepEqual(restored.filters.rule_weights, {});
  assert.equal(restored.filters.require_corroboration, false);
  assert.equal('actions' in old, false);
  assert.equal('rule_weights' in old.filters, false);
});

test('restoring explicit actions and rule weights preserves them exactly', () => {
  const saved = {
    actions: {
      spam: 'quarantine',
      publicity: 'deliver',
      malware: 'quarantine',
      quarantine_days: 30,
    },
    filters: {
      mode: 'enforce',
      require_corroboration: true,
      rule_weights: { urgency: 0 },
    },
  };
  assert.deepEqual(restoreDefaults(saved), saved);
  assert.deepEqual(deliveryPolicy(restoreDefaults(saved)), saved.actions);
});

test('legacy PUB marking follows the restored mailing settings', () => {
  assert.equal(
    deliveryPolicy({ mailing: { tag_subject: true } }).publicity,
    'tag',
  );
  assert.equal(deliveryPolicy({ mailing: null }).publicity, 'deliver');
  assert.equal(
    deliveryPolicy({ actions: null, mailing: { tag_subject: false } })
      .publicity,
    'deliver',
  );
});
