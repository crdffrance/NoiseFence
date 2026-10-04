// Query links survive authentication without adding a server-side page route.
export function qualityDestination(search: string) {
  const params = new URLSearchParams(search);
  const quality = params.get('view') === 'quality';
  const sample = params.get('sample') ?? '';
  return { quality, sample: quality && /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(sample) ? sample : '' };
}
export function qualityLink(sample: string) {
  return `/?${new URLSearchParams({ view: 'quality', sample })}`;
}
