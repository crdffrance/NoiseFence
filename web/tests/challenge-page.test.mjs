import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import test from 'node:test';

const html = readFileSync(fileURLToPath(new URL('../../src/challenge/page.html', import.meta.url)), 'utf8');
const script = html.split('<script>')[1].split('</script>')[0];
const token = 'a'.repeat(64);
const nonce = 'b'.repeat(64);
const image = Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"/>').toString('base64');

// Execute the shipped script. This small DOM supplies events, not a second
// implementation of the page or server; durable validation is tested in Rust.
function page(hash = `#${token}`, replies = [{ ok: true, json: async () => ({ nonce, image }) }, { ok: true }]) {
  const elements = new Map();
  const requests = [];
  const timeline = [];
  const location = { hash, pathname: '/challenge', search: '?ignored' };
  for (const id of ['show', 'confirm', 'confirmation', 'code', 'picture', 'result']) {
    elements.set(id, {
      value: '', textContent: '', disabled: ['show', 'confirm'].includes(id), hidden: id === 'confirmation',
      listeners: new Map(),
      addEventListener(type, listener) { this.listeners.set(type, listener); },
      focus() { this.focused = true; },
      removeAttribute(name) { delete this[name]; },
      async fire(type) { return this.listeners.get(type)?.({ preventDefault() { timeline.push('preventDefault'); } }); },
    });
  }
  vm.runInNewContext(script, {
    document: { getElementById(id) { assert(elements.has(id)); return elements.get(id); } },
    location,
    history: { replaceState(state, title, url) { timeline.push('erase'); assert.equal(url, '/challenge'); location.hash = ''; location.search = ''; } },
    fetch: async (path, options) => {
      timeline.push('fetch');
      requests.push({ path, options, body: JSON.parse(options.body) });
      const result = replies.shift();
      if (result instanceof Error) throw result;
      assert(result, 'unexpected network request');
      return result;
    },
  });
  return { elements, requests, timeline, location, get: (id) => elements.get(id) };
}

test('opening a valid or invalid link removes its fragment without fetching or confirming', () => {
  for (const hash of [`#${token}`, '#invalid', '']) {
    const p = page(hash);
    assert.deepEqual(p.timeline, ['erase']);
    assert.equal(p.requests.length, 0);
    assert.equal(p.location.hash, '');
    assert.equal(p.get('show').disabled, hash !== `#${token}`);
    assert.equal(p.get('confirmation').hidden, true);
    assert.equal(p.get('confirm').disabled, true);
  }
  assert(!html.includes('localStorage') && !html.includes('sessionStorage'));
  assert(html.includes('<noscript>') && html.includes('aria-live="polite"'));
});

test('the displayed code and explicit submit are required, secrets travel only in the JSON body', async () => {
  const p = page();
  await p.get('show').fire('click');
  assert.equal(p.requests.length, 1);
  assert.equal(p.requests[0].path, '/challenge/puzzle');
  assert.deepEqual(p.requests[0].body, { token });
  assert.equal(p.get('picture').src, `data:image/svg+xml;base64,${image}`);
  assert.equal(p.get('confirmation').hidden, false);
  assert.equal(p.get('code').focused, true);
  p.get('code').value = 'I0bad';
  await p.get('confirmation').fire('submit');
  assert.equal(p.requests.length, 1);
  p.get('code').value = 'abc234';
  await p.get('code').fire('input');
  assert.equal(p.get('code').value, 'ABC234');
  await p.get('confirmation').fire('submit');
  assert.equal(p.requests.length, 2);
  assert.equal(p.requests[1].path, '/challenge/submit');
  assert.deepEqual(p.requests[1].body, { token, nonce, code: 'ABC234' });
  for (const { path, options } of p.requests) {
    assert(!path.includes(token) && !path.includes('?'));
    assert.equal(options.method, 'POST');
    assert.equal(options.headers['Content-Type'], 'application/json');
    assert.equal(options.credentials, 'omit');
    assert.equal(options.cache, 'no-store');
    assert.equal(options.redirect, 'error');
    assert.equal(options.referrerPolicy, 'no-referrer');
  }
  assert.equal(p.get('picture').src, undefined);
  assert.equal(p.get('code').value, '');
  assert.equal(p.get('confirmation').hidden, true);
  assert.equal(p.get('show').disabled, true);
  assert.equal(p.get('confirm').disabled, true);
  assert.match(p.get('result').textContent, /Si le code et le lien étaient valides/);
  await p.get('confirmation').fire('submit');
  assert.equal(p.requests.length, 2);
});

test('image failures and hostile or oversized replies never produce a usable confirmation', async () => {
  for (const reply of [
    new Error('network'), { ok: false },
    { ok: true, json: async () => ({ nonce, image: '<script>alert(1)</script>' }) },
    { ok: true, json: async () => ({ nonce: 'wrong', image }) },
    { ok: true, json: async () => ({ nonce, image: 'A'.repeat(24001) }) },
    { ok: true, json: async () => null },
  ]) {
    const p = page(`#${token}`, [reply]);
    await p.get('show').fire('click');
    assert.equal(p.get('confirmation').hidden, true);
    assert.equal(p.get('confirm').disabled, true);
    assert.equal(p.get('picture').src, undefined);
    assert.equal(p.get('show').disabled, false);
    assert.match(p.get('result').textContent, /Réessayez ou contactez/);
    assert.equal(p.requests.length, 1);
  }
});

test('rotating a picture uses its new nonce and network failure never reports a release', async () => {
  const next = 'c'.repeat(64);
  const p = page(`#${token}`, [
    { ok: true, json: async () => ({ nonce, image }) },
    { ok: true, json: async () => ({ nonce: next, image }) },
    new Error('network'),
  ]);
  await p.get('show').fire('click');
  p.get('code').value = 'ZZZ999';
  await p.get('show').fire('click');
  assert.equal(p.get('code').value, '');
  p.get('code').value = 'ABC234';
  await p.get('confirmation').fire('submit');
  assert.equal(p.requests[2].body.nonce, next);
  assert.match(p.get('result').textContent, /Rouvrez le lien d’origine/);
  assert(!p.get('result').textContent.includes('sera libéré'));
  assert.equal(p.get('show').disabled, true);
});
