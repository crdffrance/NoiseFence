import assert from 'node:assert/strict';
import test from 'node:test';
import { euro, llmState, reputationState } from '../app/providers.ts';
const at = 1792790000;
const service = {
  installed: true,
  enabled: true,
  configuration: {
    monthly_budget_micro_eur: 20_000_000,
    pricing_checked_at: at,
  },
  budget: {
    status: 'available',
    worker_wallet: false,
    remaining_micro_eur: 100,
  },
};
test('LLM policy, pricing and wallet constraints are never represented as a healthy probe', () => {
  assert.match(llmState({ ...service, installed: false }, at), /Not installed/);
  assert.match(llmState({ ...service, enabled: false }, at), /Disabled/);
  assert.match(
    llmState(
      {
        ...service,
        configuration: {
          ...service.configuration,
          monthly_budget_micro_eur: 0,
        },
      },
      at,
    ),
    /zero budget/,
  );
  for (const pricing_checked_at of [at - 31 * 86400, at + 1, NaN])
    assert.match(
      llmState(
        {
          ...service,
          configuration: { ...service.configuration, pricing_checked_at },
        },
        at,
      ),
      /pricing verification/,
    );
  assert.match(llmState({ ...service, budget: null }, at), /unavailable/);
  assert.match(
    llmState(
      { ...service, budget: { ...service.budget, remaining_micro_eur: 0 } },
      at,
    ),
    /fully reserved/,
  );
  assert.match(
    llmState(
      {
        ...service,
        budget: {
          ...service.budget,
          remaining_micro_eur: 0,
          worker_wallet: true,
        },
      },
      at,
    ),
    /local credit/,
  );
  assert.match(llmState(service, at), /subject to selection and capacity/);
});
const state = {
  available: true,
  checked_at: at,
  policy: { crdf: true },
  loaded_keys: { crdf: true },
  quotas: { crdf: { minute: 0, day: 0 } },
  usage: { crdf: { minute_used: 100, day_used: 1000, cooldown_until: null } },
};
test('unlimited quotas never bypass cooldown and missing usage never implies zero', () => {
  assert.match(reputationState(state, 'crdf'), /upstream access not tested/);
  assert.match(
    reputationState(
      {
        ...state,
        usage: { crdf: { ...state.usage.crdf, cooldown_until: at + 60 } },
      },
      'crdf',
    ),
    /cooldown/,
  );
  assert.match(
    reputationState({ ...state, usage: { crdf: null } }, 'crdf'),
    /unavailable/,
  );
  assert.match(
    reputationState({ ...state, loaded_keys: {} }, 'crdf'),
    /not confirmed/,
  );
  assert.match(
    reputationState(
      { ...state, quotas: { crdf: { minute: 100, day: 0 } } },
      'crdf',
    ),
    /fully reserved/,
  );
  assert.match(reputationState({ ...state, policy: null }, 'crdf'), /Disabled/);
});
test('unknown accounting stays unavailable while a recorded zero remains zero', () => {
  for (const n of [null, undefined, NaN, Infinity])
    assert.equal(euro(n), 'Unavailable');
  assert.equal(euro(0), '€0.00');
  assert.equal(euro(2_500_000), '€2.50');
});
