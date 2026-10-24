// Query links survive authentication without adding a server-side page route.
export type ResearchTab = 'samples' | 'comparison' | 'reliability';

export function researchDestination(search: string): ResearchTab | null {
  const params = new URLSearchParams(search);
  if (params.get('view') !== 'quality') return null;
  const tab = params.get('tab');
  return tab === 'comparison' || tab === 'reliability' ? tab : 'samples';
}

export function researchTabFor(
  section: string,
  filter: string,
): ResearchTab | null {
  if (section === 'quality') return 'samples';
  if (section === 'reliability') return 'reliability';
  return section === 'messages' && filter.startsWith('rspamd_')
    ? 'comparison'
    : null;
}

// Keep unrelated query parameters; sample identifiers only belong to the samples tab.
export function researchSearch(
  search: string,
  tab: ResearchTab | null,
): string {
  const params = new URLSearchParams(search);
  if (tab) {
    params.set('view', 'quality');
    params.set('tab', tab);
  } else {
    params.delete('view');
    params.delete('tab');
  }
  if (tab !== 'samples') params.delete('sample');
  const query = params.toString();
  return query ? `?${query}` : '';
}
export function qualityDestination(search: string) {
  const params = new URLSearchParams(search);
  const quality = params.get('view') === 'quality';
  const sample = params.get('sample') ?? '';
  return {
    quality,
    sample:
      quality &&
      researchDestination(search) === 'samples' &&
      /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(
        sample,
      )
        ? sample
        : '',
  };
}
export function qualityLink(sample: string) {
  return `/?${new URLSearchParams({ view: 'quality', sample })}`;
}
