/** Compare JSON settings, preserving array order and the difference between null and absence. */
export type SettingChange = { path: string[]; before: unknown; after: unknown };
export function canonicalSetting(value: unknown): string | undefined {
  return JSON.stringify(value, (_key, item) =>
    item && typeof item === 'object' && !Array.isArray(item)
      ? Object.fromEntries(
          Object.keys(item)
            .sort()
            .map((key) => [key, item[key]]),
        )
      : item,
  );
}
export function settingChanges(
  before: unknown,
  after: unknown,
): SettingChange[] {
  const out: SettingChange[] = [];
  const pending: SettingChange[] = [{ path: [], before, after }];
  let visited = 0;
  while (pending.length) {
    const row = pending.pop()!;
    if (canonicalSetting(row.before) === canonicalSetting(row.after)) continue;
    const a = row.before,
      b = row.after;
    const comparable =
      a !== null &&
      b !== null &&
      typeof a === 'object' &&
      typeof b === 'object' &&
      Array.isArray(a) === Array.isArray(b);
    // Collapse a large/deep subtree as one explicit changed value, never silently omit it.
    if (comparable && row.path.length < 12 && ++visited <= 2000) {
      const keys = [...new Set([...Object.keys(a), ...Object.keys(b)])].sort();
      for (const key of keys.reverse())
        pending.push({
          path: [...row.path, key],
          before: Object.hasOwn(a, key)
            ? (a as Record<string, unknown>)[key]
            : undefined,
          after: Object.hasOwn(b, key)
            ? (b as Record<string, unknown>)[key]
            : undefined,
        });
    } else out.push(row);
  }
  return out;
}
export function changePath(path: string[]): string {
  return path.length
    ? '/' +
        path.map((v) => v.replaceAll('~', '~0').replaceAll('/', '~1')).join('/')
    : '/';
}
export function settingValue(value: unknown): string {
  return value === undefined ? 'Not set' : JSON.stringify(value, null, 2);
}
export const settingSections: Record<string, string> = {
  domains: 'Domains',
  gateways: 'Gateways',
  filters: 'Filter policy',
  actions: 'Delivery actions',
  identity_directory: 'Directory snapshot',
  contact_learning: 'Automatic correspondent memory',
  protection: 'Protection & reputation',
  mailing: 'Marketing',
  research_archive: 'Research archive',
  smtp_admission: 'SMTP admission',
  rbl: 'DNS blocklists',
  detection: 'Detection engines',
  preferences: 'Personal preferences',
  custom_filtering: 'Rules & profiles',
  quality_candidate: 'Shadow candidate',
};
export function auditDescription(action: string): string {
  const names: Record<string, string> = {
    configuration: 'Configuration revision recorded',
    configuration_staged: 'Activation proposal staged',
    configuration_aborted: 'Activation proposal cancelled',
    configuration_recovered: 'Previous policy recovery requested',
    account: 'Account changed',
    retry: 'Delivery retry requested',
    login: 'Signed in',
    feedback: 'Classification corrected',
    provider_key: 'Provider credential saved',
    managed_key: 'Provider credential saved',
    quarantine_release: 'Quarantined delivery released',
    quarantine_delete: 'Quarantined delivery discarded',
    quarantine_expire: 'Quarantine retention expired',
    cluster_quarantine_request: 'Remote quarantine action requested',
    model_set_retained: 'Model set retained',
    model_set_removed: 'Retained model set removed',
  };
  return Object.hasOwn(names, action)
    ? names[action]
    : action.replaceAll('_', ' ');
}
export function auditRevision(action: string, object: string): number | null {
  if (action !== 'configuration' || !/^\d+$/.test(object)) return null;
  const id = Number(object);
  return Number.isSafeInteger(id) ? id : null;
}

/** These sections edit one shared draft. Wizards still require an explicit exit. */
export function keepsConfigurationDraft(
  from: string,
  to: string,
  wizardOpen: boolean,
): boolean {
  const editors = ['domains', 'gateways', 'filters', 'server'];
  return !wizardOpen && editors.includes(from) && editors.includes(to);
}

export function settingTitle(path: string[]): string {
  if (path[0] === 'contact_learning') return ({enabled:'Learn from accepted messages',retention_days:'Memory window (days)',minimum_campaigns:'Minimum distinct campaigns',minimum_days:'Minimum observation days',learn_since:'Exclude history before (Unix time)'} as Record<string,string>)[path[1]] ?? 'Automatic correspondent memory';
  if (path[0] === 'identity_directory' && path[1] === 'sha256') return 'Prepared catalog SHA-256';
  if (path[0] === 'identity_directory' && path[1] === 'reviewed_from') return 'Reviewed installed catalog SHA-256';
  if (path[0] === 'protection' && path[1] === 'protected_names') {
    const row = path[2] && /^\d+$/.test(path[2]) ? ` ${Number(path[2]) + 1}` : '';
    const detail = path[3] === 'name' ? ' · display name' : path[3] === 'domain' ? ' · sending domain' : '';
    return `Protected name${row}${detail}`;
  }
  if (path[0] === 'protection' && path[1] === 'identity') return 'Observe identity signals';
  const field = path.at(-1) ?? 'configuration';
  const names: Record<string, string> = {
    threshold: 'Content reference threshold',
    quarantine_days: 'Quarantine retention (days)',
    minimum_providers: 'Independent reputation providers required',
    require_corroboration: 'Corroborating evidence required',
    mode: 'Operating mode',
    recipient_verification: 'Verify recipients at destination',
    unknown_recipient_fallback: 'Unknown-recipient fallback',
    accept_all_recipients: 'Accept any address in the domain',
    partial_actions: 'Actions with sufficient partial evidence',
    resolve_uncertain_by_score: 'Legacy score-resolution setting',
  };
  if (Object.hasOwn(names, field)) return names[field];
  const text = field.replaceAll('_', ' ');
  return text.charAt(0).toUpperCase() + text.slice(1);
}
