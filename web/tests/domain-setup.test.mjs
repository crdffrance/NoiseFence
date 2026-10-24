import assert from 'node:assert/strict';
import test from 'node:test';
import {
  prepareDomain,
  setupProblem,
  checkSummary,
} from '../app/domain-setup.ts';

const settings = {
  domains: [{ name: 'old.test' }],
  gateways: [
    { id: 'g', name: 'Provider', hosts: ['inbound.provider.test'], port: 25 },
  ],
  filters: { mode: 'observe', threshold: 95 },
  actions: { spam: 'quarantine' },
  detection: { modules: { llm: { enabled: false } } },
};
const draft = () => ({
  name: ' New.Test ',
  gatewayId: 'g',
  newGateway: {
    id: 'n',
    name: 'New gateway',
    hosts: [' INBOUND.EXAMPLE.TEST '],
    port: 25,
  },
  recipientMode: 'verify',
  recipients: '',
});
test('domain setup preserves policies and defaults to verified recipients without fallback', () => {
  const result = prepareDomain(settings, draft());
  assert.equal(result.filters, settings.filters);
  assert.equal(result.actions, settings.actions);
  assert.equal(result.detection, settings.detection);
  assert.equal(settings.domains.length, 1);
  assert.equal(result.domains[1].name, 'new.test');
  assert.equal(result.domains[1].accept_all_recipients, true);
  assert.equal(result.domains[1].recipient_verification.timeout_ms, 8000);
  assert.equal(result.domains[1].unknown_recipient_fallback, undefined);
  assert.equal(setupProblem(settings, draft(), 'mx.test', 3), null);
});
test('explicit lists and new routes remain separate from wildcard verification', () => {
  const value = {
    ...draft(),
    gatewayId: '',
    recipientMode: 'explicit',
    recipients: 'Alice@new.test\n\n bob@new.test ',
  };
  assert.equal(setupProblem(settings, value, 'mx.test', 3), null);
  const result = prepareDomain(settings, value);
  assert.deepEqual(result.domains[1].recipients, [
    'Alice@new.test',
    'bob@new.test',
  ]);
  assert.equal(result.domains[1].accept_all_recipients, false);
  assert.equal(result.domains[1].recipient_verification, null);
  assert.deepEqual(result.gateways[1].hosts, ['inbound.example.test']);
  assert.equal(result.domains[1].gateway, 'n');
});
test('setup catches duplicates, route loops, invalid ports and out-of-domain recipients', () => {
  for (const name of [
    'old.test',
    'https://new.test',
    'x..test',
    'mail@new.test',
    'é.test',
  ])
    assert.ok(setupProblem(settings, { ...draft(), name }, 'mx.test', 3));
  for (const hosts of [
    ['new.test'],
    ['mx.test.'],
    ['old.test'],
    ['https://provider.test'],
    ['x:0'],
    ['x:65536'],
    ['x:25:1'],
    [],
  ])
    assert.ok(
      setupProblem(
        settings,
        {
          ...draft(),
          gatewayId: '',
          newGateway: { ...draft().newGateway, hosts },
        },
        'mx.test',
        3,
      ),
    );
  for (const recipients of [
    '',
    'user@other.test',
    '@new.test',
    'a@new.test\r\nDATA',
  ])
    assert.ok(
      setupProblem(
        settings,
        { ...draft(), recipientMode: 'explicit', recipients },
        'mx.test',
        3,
      ),
    );
  for (const port of [0, 65536, NaN, 25.5])
    assert.ok(
      setupProblem(
        settings,
        {
          ...draft(),
          gatewayId: '',
          newGateway: { ...draft().newGateway, port },
        },
        'mx.test',
        3,
      ),
    );
});
test('check explanations distinguish SMTP acceptance, missing recipients, DNS and real delivery', () => {
  const summary = (result) => checkSummary({ result });
  assert.match(
    summary({ check: 'recipient', status: 'accepted' }),
    /No message was sent/,
  );
  assert.match(
    summary({ check: 'recipient', status: 'unavailable' }),
    /does not prove the address is missing/,
  );
  assert.match(
    summary({ check: 'recipient', status: 'unknown' }),
    /nonexistent/,
  );
  assert.match(
    summary({ check: 'dns', status: 'available', local_mx_present: true }),
    /does not verify delivery/,
  );
  assert.match(
    summary({ check: 'dns', status: 'available', local_mx_present: false }),
    /Keep the current route/,
  );
  assert.match(
    summary({ check: 'dns', status: 'null_mx' }),
    /does not accept mail/,
  );
  assert.match(
    summary({ check: 'configuration', status: 'valid' }),
    /has not been applied/,
  );
});
