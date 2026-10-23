import assert from 'node:assert/strict';
import test from 'node:test';
import { qualityDestination, qualityLink } from '../app/quality-link.ts';
test('annotation links survive authentication and validate the batch identifier', () => {
  const id = 'e993dc6a-4aec-475a-a041-6c03922a95cf';
  assert.deepEqual(qualityDestination(qualityLink(id).slice(1)), {
    quality: true,
    sample: id,
  });
  assert.deepEqual(qualityDestination('?view=quality'), {
    quality: true,
    sample: '',
  });
  for (const search of [
    '?view=quality&sample=../../admin',
    '?view=quality&sample=https://evil.test',
  ]) {
    assert.deepEqual(qualityDestination(search), { quality: true, sample: '' });
  }
  assert.deepEqual(qualityDestination(`?view=messages&sample=${id}`), {
    quality: false,
    sample: '',
  });
});

test('research deep links restore all tabs without treating another tab as an annotation sample', async () => {
  const { researchDestination, researchTabFor, researchSearch } =
    await import('../app/quality-link.ts');
  const id = 'e993dc6a-4aec-475a-a041-6c03922a95cf';
  assert.equal(researchDestination('?view=quality'), 'samples');
  assert.equal(researchDestination('?view=messages&tab=comparison'), null);
  assert.equal(
    researchDestination('?view=quality&tab=https://example.test'),
    'samples',
  );
  for (const tab of ['samples', 'comparison', 'reliability']) {
    const search = researchSearch(`?case=ham&view=quality&sample=${id}`, tab);
    assert.equal(researchDestination(search), tab);
    assert.equal(new URLSearchParams(search).get('case'), 'ham');
    assert.equal(
      qualityDestination(search).sample,
      tab === 'samples' ? id : '',
    );
  }
  assert.equal(
    researchSearch(`?view=quality&tab=comparison&sample=${id}`, null),
    '',
  );
  assert.equal(researchTabFor('messages', 'rspamd_disagreement'), 'comparison');
  assert.equal(researchTabFor('messages', 'quarantined'), null);
  assert.equal(researchTabFor('quality', 'all'), 'samples');
  assert.equal(researchTabFor('reliability', 'all'), 'reliability');
  assert.equal(researchTabFor('filters', 'rspamd_all'), null);
});
