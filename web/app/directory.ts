// Directory drafts contain explicit administrator assignments, never routing grants.
export type Activity = 'active' | 'inactive' | 'unknown';
export type Role =
  | 'executive'
  | 'finance'
  | 'helpdesk'
  | 'legal'
  | 'supplier'
  | 'custom';
export const roles: Role[] = [
  'executive',
  'finance',
  'helpdesk',
  'legal',
  'supplier',
  'custom',
];
export type Source = {
  id: string;
  label: string;
  provider: string;
  authority: string;
  scopes: string[];
  stale_after_seconds: number;
};
export type Person = {
  id: string;
  display_name: string;
  kind: 'person' | 'shared_mailbox' | 'supplier';
  activity: Activity;
  addresses: string[];
  protected_roles: Role[];
};
export type Group = {
  id: string;
  display_name: string;
  activity: Activity;
  addresses: string[];
  protected: boolean;
};
export type Membership = {
  group: string;
  member: { kind: 'person' | 'group'; id: string };
};
export type Delegation = { owner: string; delegate: string; address: string };
export type DirectoryDraft = {
  source: Source;
  people: Person[];
  groups: Group[];
  memberships: Membership[];
  delegations: Delegation[];
};
export type DirectorySelection = {
  sha256: string | null;
  reviewed_from?: string | null;
};
export type SourceStatus = {
  source: Source;
  generation: number;
  completed_at: number;
  fresh: boolean;
  people: number;
  groups: number;
  protected_people: number;
  protected_groups: number;
  memberships: number;
  delegations: number;
};
export type DirectoryView = {
  revision: number;
  catalog_sha256: string | null;
  observation_only: boolean;
  sources: SourceStatus[];
  draft: DirectoryDraft | null;
};
export type DirectoryEdit =
  | { operation: 'upsert_manual'; draft: DirectoryDraft }
  | { operation: 'remove'; source_id: string };
type Counts = { added: number; removed: number; changed: number };
export type DirectoryPrepared = {
  revision: number;
  selection: DirectorySelection;
  active: false;
  review: {
    operation: string;
    source_id: string;
    source_label: string;
    people: Counts;
    groups: Counts;
    membership_changes: number;
    delegation_changes: number;
    removed_or_disabled: number;
    protected_identity_changes: number;
    source_configuration_changed: boolean;
    requires_attention: boolean;
    before: SourceStatus | null;
    after: SourceStatus | null;
  };
};
export const MAX_PEOPLE_CSV_BYTES = 4 * 1024 * 1024;
const bytes = (s: string) => new TextEncoder().encode(s).length;
export function plainText(s: string, maximum: number) {
  if (!s.trim() || bytes(s) > maximum) return false;
  for (const c of s) {
    const n = c.codePointAt(0)!;
    if (
      n < 32 ||
      (n >= 127 && n <= 159) ||
      (n >= 0x202a && n <= 0x202e) ||
      (n >= 0x2066 && n <= 0x2069)
    )
      return false;
  }
  return true;
}
export function addressList(text: string): string[] {
  return [
    ...new Set(
      text
        .split(/[;\n]/)
        .map((s) => s.trim())
        .filter(Boolean)
        .map((value) => {
          const at = value.lastIndexOf('@');
          return at >= 0
            ? value.slice(0, at + 1) + value.slice(at + 1).toLowerCase()
            : value;
        }),
    ),
  ];
}
export function identityError(p: Person | Group): string | null {
  if (!plainText(p.id, 256))
    return 'A stable ID of 1–256 UTF-8 bytes is required.';
  if (!plainText(p.display_name, 200))
    return 'Enter a display name without control characters.';
  if (!['active', 'inactive', 'unknown'].includes(p.activity))
    return 'Select an activity state.';
  if (
    p.addresses.length > 32 ||
    p.addresses.some(
      (a) => !/^[^\s@<>]+@[^\s@<>]+$/.test(a) || !plainText(a, 320),
    )
  )
    return 'Use explicit email addresses, up to 32 per identity.';
  if (
    'protected_roles' in p &&
    (p.protected_roles.some((r) => !roles.includes(r)) ||
      !['person', 'shared_mailbox', 'supplier'].includes(p.kind))
  )
    return 'Select a supported identity type and protected roles.';
  return null;
}
export function sourceError(source: Source, domains: string[]) {
  if (
    !plainText(source.id, 100) ||
    !plainText(source.label, 200) ||
    !plainText(source.authority, 256)
  )
    return 'Source ID, name and authority are required.';
  if (source.provider !== 'manual')
    return 'Provider sources are read-only in this workspace.';
  if (!source.scopes.length || source.scopes.some((s) => !domains.includes(s)))
    return 'Choose at least one installed receiving domain.';
  if (
    !Number.isInteger(source.stale_after_seconds) ||
    source.stale_after_seconds < 300 ||
    source.stale_after_seconds > 2592000
  )
    return 'Freshness must be between 5 minutes and 30 days.';
  return null;
}
export function newDirectory(domains: string[]): DirectoryDraft {
  return {
    source: {
      id: '',
      label: '',
      provider: 'manual',
      authority: 'organization',
      scopes: domains.length === 1 ? [...domains] : [],
      stale_after_seconds: 2592000,
    },
    people: [],
    groups: [],
    memberships: [],
    delegations: [],
  };
}
export function directoryPending(
  selection: DirectorySelection | null | undefined,
  installed: string | null,
) {
  return (
    selection !== null &&
    selection !== undefined &&
    selection.sha256 !== installed
  );
}
export function preparedMatches(
  prepared: DirectoryPrepared,
  revision: number,
  installed: string | null,
) {
  return (
    prepared.active === false &&
    prepared.revision === revision &&
    (prepared.selection.reviewed_from ?? null) === installed
  );
}
// RFC 4180-style parser with strict field/row limits. No remote fetch or formula evaluation.
export function parsePeopleCsv(text: string): Person[] {
  if (bytes(text) > MAX_PEOPLE_CSV_BYTES)
    throw new Error('People CSV must be at most 4 MiB.');
  text = text.replace(/^\uFEFF/, '');
  const rows: string[][] = [];
  let row: string[] = [],
    field = '',
    quoted = false,
    closed = false;
  const cell = () => {
    if (bytes(field) > 16384) throw new Error('A CSV field exceeds 16 KiB.');
    row.push(field);
    field = '';
    closed = false;
    if (row.length > 6) throw new Error('Expected exactly six CSV columns.');
  };
  const line = () => {
    cell();
    if (row.some(Boolean)) rows.push(row);
    row = [];
    if (rows.length > 20001)
      throw new Error('At most 20,000 people can be imported.');
  };
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          quoted = false;
          closed = true;
        }
      } else field += c;
    } else if (c === '"') {
      if (field || closed) throw new Error('Invalid CSV quoting.');
      quoted = true;
    } else if (c === ',') cell();
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      line();
    } else {
      if (closed) throw new Error('Unexpected text after a quoted field.');
      field += c;
    }
    if (field.length > 16384) throw new Error('A CSV field exceeds 16 KiB.');
  }
  if (quoted) throw new Error('Unclosed CSV quote.');
  if (field || row.length || closed) line();
  if (rows.shift()?.join(',') !== 'id,name,addresses,kind,activity,roles')
    throw new Error('Expected header: id,name,addresses,kind,activity,roles');
  if (!rows.length) throw new Error('The file contains no people.');
  const ids = new Set<string>();
  return rows.map((cells, i) => {
    if (cells.length !== 6)
      throw new Error(`Row ${i + 2}: expected six columns.`);
    const [id, display_name, addresses, kind, activity, protected_roles] =
      cells.map((s) => s.trim());
    const person: Person = {
      id,
      display_name,
      addresses: addressList(addresses),
      kind: kind as Person['kind'],
      activity: activity as Activity,
      protected_roles: [
        ...new Set(protected_roles.split(';').filter(Boolean)),
      ] as Role[],
    };
    const error = identityError(person);
    if (error) throw new Error(`Row ${i + 2}: ${error}`);
    if (ids.has(id)) throw new Error(`Row ${i + 2}: duplicate ID ${id}.`);
    ids.add(id);
    return person;
  });
}
export function mergePeople(current: Person[], imported: Person[]) {
  const map = new Map(current.map((p) => [p.id, p]));
  let added = 0,
    changed = 0;
  for (const p of imported) {
    const old = map.get(p.id);
    if (!old) added++;
    else if (JSON.stringify(old) !== JSON.stringify(p)) changed++;
    map.set(p.id, p);
  }
  if (map.size > 20000)
    throw new Error('The merged directory exceeds 20,000 people.');
  return { people: [...map.values()], added, changed };
}
export function removePerson(
  draft: DirectoryDraft,
  id: string,
): DirectoryDraft {
  return {
    ...draft,
    people: draft.people.filter((p) => p.id !== id),
    memberships: draft.memberships.filter(
      (m) => m.member.kind !== 'person' || m.member.id !== id,
    ),
    delegations: draft.delegations.filter(
      (d) => d.owner !== id && d.delegate !== id,
    ),
  };
}
export function removeGroup(draft: DirectoryDraft, id: string): DirectoryDraft {
  return {
    ...draft,
    groups: draft.groups.filter((g) => g.id !== id),
    memberships: draft.memberships.filter(
      (m) =>
        m.group !== id && (m.member.kind !== 'group' || m.member.id !== id),
    ),
  };
}
