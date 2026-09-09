import assert from 'node:assert/strict';
import test from 'node:test';
import { api } from '../app/client.ts';

test('diagnostic GET preserves session authentication, skips cache and accepts cancellation', async (t) => {
  const controller = new AbortController();
  t.mock.method(globalThis, 'fetch', async (url, init) => {
    assert.equal(url, '/api/v1/messages/example/diagnostics');
    assert.equal(init.credentials, 'same-origin');
    assert.equal(init.method, 'GET');
    assert.equal(init.body, undefined);
    assert.equal(init.signal, controller.signal);
    assert.equal(init.cache, 'no-store');
    return Response.json({ message_id: 'example' });
  });
  assert.deepEqual(
    await api('/messages/example/diagnostics', undefined, undefined, {
      signal: controller.signal,
      cache: 'no-store',
    }),
    { message_id: 'example' },
  );
});

test('authenticated POST behavior is preserved for existing callers', async (t) => {
  t.mock.method(globalThis, 'fetch', async (_url, init) => {
    assert.equal(init.credentials, 'same-origin');
    assert.equal(init.method, 'POST');
    assert.equal(init.headers['X-CSRF-Token'], 'test-csrf');
    assert.equal(init.body, '{"action":"release"}');
    return Response.json({ ok: true });
  });
  await api('/messages/example/quarantine', { action: 'release' }, 'test-csrf');
});

test('scoped diagnostic history uses the delivery query with authentication and cancellation', async (t) => {
  const controller = new AbortController();
  t.mock.method(globalThis, 'fetch', async (url, init) => {
    assert.equal(url, '/api/v1/messages/example/diagnostics?delivery_id=123');
    assert.equal(init.credentials, 'same-origin');
    assert.equal(init.method, 'GET');
    assert.equal(init.cache, 'no-store');
    assert.equal(init.signal, controller.signal);
    return Response.json({
      message_id: 'example',
      recipients: [{ delivery_id: 123 }],
    });
  });
  const result = await api(
    '/messages/example/diagnostics?delivery_id=123',
    undefined,
    undefined,
    { signal: controller.signal, cache: 'no-store' },
  );
  assert.deepEqual(result.recipients, [{ delivery_id: 123 }]);
});

test('failed diagnostics expose an error suitable for the retry state', async (t) => {
  t.mock.method(globalThis, 'fetch', async () =>
    Response.json({ error: 'Service indisponible' }, { status: 503 }),
  );
  await assert.rejects(
    api('/messages/example/diagnostics'),
    /Service indisponible/,
  );
});

test('aborted diagnostic requests remain aborts instead of becoming empty diagnostics', async (t) => {
  const controller = new AbortController();
  controller.abort();
  t.mock.method(globalThis, 'fetch', async (_url, init) =>
    init.signal.throwIfAborted(),
  );
  await assert.rejects(
    api('/messages/example/diagnostics', undefined, undefined, {
      signal: controller.signal,
    }),
    { name: 'AbortError' },
  );
});
