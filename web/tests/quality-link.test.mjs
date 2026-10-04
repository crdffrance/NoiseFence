import assert from 'node:assert/strict';
import test from 'node:test';
import { qualityDestination, qualityLink } from '../app/quality-link.ts';
test('annotation links survive authentication and validate the batch identifier', () => {
  const id = 'e993dc6a-4aec-475a-a041-6c03922a95cf';
  assert.deepEqual(qualityDestination(qualityLink(id).slice(1)), { quality: true, sample: id });
  assert.deepEqual(qualityDestination('?view=quality'), { quality: true, sample: '' });
  for (const search of ['?view=quality&sample=../../admin', '?view=quality&sample=https://evil.test']) {
    assert.deepEqual(qualityDestination(search), { quality: true, sample: '' });
  }
  assert.deepEqual(qualityDestination(`?view=messages&sample=${id}`), { quality: false, sample: '' });
});
