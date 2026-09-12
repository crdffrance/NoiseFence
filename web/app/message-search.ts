export type SearchFilters = {
  sender: string;
  recipient: string;
  subject: string;
  rule: string;
  id: string;
  status: string;
  after: string;
  before: string;
  min_score: string;
  max_score: string;
};
export const emptySearch: SearchFilters = {
  sender: '',
  recipient: '',
  subject: '',
  rule: '',
  id: '',
  status: '',
  after: '',
  before: '',
  min_score: '',
  max_score: '',
};
export function searchFilterCount(filters: SearchFilters) {
  return Object.values(filters).filter((value) => value.trim() !== '').length;
}
function day(value: string, end: boolean) {
  const parts = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (!parts) throw new Error('Date invalide.');
  const [, y, m, d] = parts.map(Number);
  const date = new Date(y, m - 1, d);
  if (
    date.getFullYear() !== y ||
    date.getMonth() !== m - 1 ||
    date.getDate() !== d
  )
    throw new Error('Date invalide.');
  // Calendar arithmetic keeps the entire selected day, including DST changes.
  if (end) date.setDate(date.getDate() + 1);
  return Math.floor(date.getTime() / 1000);
}
export function searchParameters(
  q: string,
  filter: string,
  domain: string,
  offset: number,
  filters: SearchFilters,
) {
  const params = new URLSearchParams({
    q,
    filter,
    domain,
    offset: String(offset),
  });
  for (const field of [
    'sender',
    'recipient',
    'subject',
    'rule',
    'id',
    'status',
  ] as const) {
    if (filters[field].trim()) params.set(field, filters[field].trim());
  }
  const after = filters.after ? day(filters.after, false) : undefined;
  const before = filters.before ? day(filters.before, true) : undefined;
  if (after !== undefined && before !== undefined && after >= before)
    throw new Error('La date de début doit précéder ou égaler la date de fin.');
  if (after !== undefined) params.set('after', String(after));
  if (before !== undefined) params.set('before', String(before));
  for (const field of ['min_score', 'max_score'] as const) {
    if (filters[field].trim() !== '') {
      const value = Number(filters[field]);
      if (!Number.isFinite(value) || value < 0 || value > 100)
        throw new Error('Le score doit être compris entre 0 et 100.');
      params.set(field, String(value));
    }
  }
  if (
    params.has('min_score') &&
    params.has('max_score') &&
    Number(params.get('min_score')) > Number(params.get('max_score'))
  )
    throw new Error('Le score minimum dépasse le maximum.');
  return params.toString();
}
