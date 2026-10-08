import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import vm from 'node:vm';
const source = fs.readFileSync(new URL('../../src/api/sender_verification.js', import.meta.url), 'utf8');
async function page({ token = 'ticket.signature', confirmStatus = 200 } = {}) {
  const nodes = new Map(), calls = [], external = [], history = [];
  const get = (id) => {
    if (!nodes.has(id)) nodes.set(id, { value: '', disabled: id === 'confirm', hidden: true, textContent: '', listeners: {}, addEventListener(type, fn) { this.listeners[type] = fn; }, removeAttribute(name) { delete this[name]; } });
    return nodes.get(id);
  };
  let serial = 0;
  const context = {
    location: { hash: token ? '#' + token : '', pathname: '/verify-sender' },
    history: { replaceState: (...args) => history.push(args) },
    document: { getElementById: get, createElement: () => ({}), head: { appendChild: (s) => external.push(s.src) } },
    window: {},
    fetch: async (url, options) => {
      calls.push({ url, options, body: JSON.parse(options.body) });
      const status = url.endsWith('/confirm') ? confirmStatus : 200;
      return { ok: status === 200, status, json: async () => url.endsWith('/info') ? { provider: 'self_hosted', id: 'ticket' } : url.endsWith('/challenge') ? { id: 'challenge-' + ++serial, image: 'data:image/png;base64,cG5n', expires: Math.floor(Date.now() / 1000) + 300 } : { confirmed: true } };
    },
  };
  await vm.runInNewContext(source, context);
  return { get, calls, external, history };
}
test('local verification loads only first-party resources and requires an explicit answer and click', async () => {
  const p = await page();
  assert.deepEqual(p.external, []);
  assert.equal(p.history[0][2], '/verify-sender');
  assert.equal(p.get('local').hidden, false);
  assert.equal(p.get('confirm').disabled, true);
  assert.equal(p.calls.length, 2);
  assert.ok(p.calls.every((c) => c.url.startsWith('/api/v1/sender-verification/') && !c.url.includes('signature') && c.options.credentials === 'omit'));
  p.get('answer').value = 'ac234y';
  p.get('answer').listeners.input();
  assert.equal(p.get('confirm').disabled, false);
  await p.get('confirm').listeners.click();
  assert.equal(p.calls.length, 3);
  assert.deepEqual(JSON.parse(p.calls[2].body.captcha), { id: 'challenge-1', answer: 'ac234y' });
  assert.match(p.get('status').textContent, /Confirmed/);
  await p.get('confirm').listeners.click();
  assert.equal(p.calls.length, 3, 'completed proofs cannot be submitted again');
});
test('a failed answer requires a fresh image; the page does not loop on confirmation', async () => {
  const p = await page({ confirmStatus: 422 });
  p.get('answer').value = 'wrong!';p.get('answer').listeners.input();
  await p.get('confirm').listeners.click();
  assert.equal(p.get('confirm').disabled, true);
  assert.equal(p.get('answer').value, '');
  assert.match(p.get('status').textContent, /new image/);
  await p.get('refresh').listeners.click();
  p.get('answer').value = 'AC234Y';p.get('answer').listeners.input();
  await p.get('confirm').listeners.click();
  assert.equal(JSON.parse(p.calls.at(-1).body.captcha).id, 'challenge-2');
});
test('missing capability links perform no request and rate limiting gives an explicit retry delay', async () => {
  const missing = await page({ token: '' });
  assert.equal(missing.calls.length, 0);
  assert.match(missing.get('status').textContent, /complete verification link/);
  const limited = await page({ confirmStatus: 429 });
  limited.get('answer').value = 'AC234Y';limited.get('answer').listeners.input();
  await limited.get('confirm').listeners.click();
  assert.match(limited.get('status').textContent, /wait a minute/);
  assert.equal(limited.get('confirm').disabled, true);
});
