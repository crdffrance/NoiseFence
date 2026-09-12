import assert from 'node:assert/strict';
import test from 'node:test';
import {
  emptySearch,
  searchFilterCount,
  searchParameters,
} from '../app/message-search.ts';

test('advanced criteria are encoded without widening the recipient or domain scope', () => {
  const filters = {
    ...emptySearch,
    recipient: 'alice+test@example.test',
    subject: 'réunion & facture',
    min_score: '0',
    max_score: '20',
    status: 'delivered',
  };
  const p = new URLSearchParams(
    searchParameters(
      '"équipe Paris"',
      'incomplete',
      'example.test',
      50,
      filters,
    ),
  );
  assert.equal(p.get('q'), '"équipe Paris"');
  assert.equal(p.get('domain'), 'example.test');
  assert.equal(p.get('recipient'), filters.recipient);
  assert.equal(p.get('min_score'), '0');
  assert.equal(p.get('offset'), '50');
  assert.equal(searchFilterCount(filters), 5);
  assert.equal(searchFilterCount(emptySearch), 0);
});
test('inclusive date range uses calendar boundaries and rejects invalid dates or scores', () => {
  const p = new URLSearchParams(
    searchParameters('', 'all', '', 0, {
      ...emptySearch,
      after: '2026-03-29',
      before: '2026-03-29',
    }),
  );
  assert.equal(Number(p.get('after')), new Date(2026, 2, 29).getTime() / 1000);
  assert.equal(Number(p.get('before')), new Date(2026, 2, 30).getTime() / 1000);
  for (const criteria of [
    { after: '2026-02-30' },
    { before: 'invalid' },
    { after: '2026-09-12', before: '2026-09-10' },
    { min_score: 'NaN' },
    { max_score: '101' },
    { min_score: '90', max_score: '0' },
  ])
    assert.throws(() =>
      searchParameters('', 'all', '', 0, { ...emptySearch, ...criteria }),
    );
});
