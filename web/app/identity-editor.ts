export type ProtectedName = { name: string; domain: string };
export const MAX_PROTECTED_NAMES = 100;
export const MAX_IDENTITY_CSV_BYTES = 65536;
const bytes = (value: string) => new TextEncoder().encode(value).length;
export function normalizeProtectedName(value: ProtectedName): ProtectedName {
  return { name: value.name.trim(), domain: value.domain.trim().toLowerCase() };
}
export function protectedNameError(value: ProtectedName): string | null {
  const { name, domain } = normalizeProtectedName(value);
  if (bytes(name) < 3 || bytes(name) > 100 || /[\p{Cc}\p{Cf}]/u.test(name))
    return 'Use a name of 3–100 UTF-8 bytes, without control or invisible formatting characters.';
  if (
    !domain ||
    domain.length > 253 ||
    !domain
      .split('.')
      .every(
        (label) =>
          label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label),
      )
  )
    return 'Enter an ASCII domain, without an email address, URL, wildcard or trailing dot. Use punycode for international domains.';
  return null;
}
export function protectedNameConflicts(entries: ProtectedName[]): string[] {
  const groups = new Map<string, Set<string>>();
  for (const entry of entries) {
    const { name, domain } = normalizeProtectedName(entry);
    if (!name || !domain) continue;
    const key = name.toLowerCase();
    const domains = groups.get(key) ?? new Set<string>();
    domains.add(domain);
    groups.set(key, domains);
  }
  return [...groups]
    .filter(([, domains]) => domains.size > 1)
    .map(([name]) => name);
}
export function matchesProtectedName(
  entry: ProtectedName,
  query: string,
): boolean {
  const term = query.trim().toLowerCase();
  return `${entry.name} ${entry.domain}`.toLowerCase().includes(term);
}
// Deliberately small CSV dialect: exactly two columns, optional quoted fields,
// CRLF/LF and a UTF-8 BOM. No formula evaluation, arbitrary headers or sniffing.
export function parseIdentityCsv(text: string): ProtectedName[] {
  if (bytes(text) > MAX_IDENTITY_CSV_BYTES)
    throw new Error('The CSV must be at most 64 KiB.');
  text = text.replace(/^\uFEFF/, '');
  const rows: string[][] = [];
  let row: string[] = [],
    cell = '',
    quoted = false,
    closed = false;
  const pushCell = () => {
    row.push(cell);
    cell = '';
    closed = false;
  };
  const pushRow = () => {
    pushCell();
    if (row.some((value) => value.length > 0)) rows.push(row);
    row = [];
    if (rows.length > MAX_PROTECTED_NAMES + 1)
      throw new Error('The CSV may contain at most 100 names plus its header.');
  };
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') {
        cell += '"';
        i++;
      } else if (c === '"') {
        quoted = false;
        closed = true;
      } else cell += c;
    } else if (c === ',' || c === '\n' || c === '\r') {
      if (c === ',') {
        pushCell();
        if (row.length > 2)
          throw new Error('Expected exactly two columns: name,domain.');
      } else {
        pushRow();
        if (c === '\r' && text[i + 1] === '\n') i++;
      }
    } else if (c === '"' && cell === '' && !closed) quoted = true;
    else {
      if (closed || c === '"')
        throw new Error(
          'Invalid CSV quoting. Use double quotes around a field containing commas.',
        );
      cell += c;
    }
  }
  if (quoted) throw new Error('A quoted CSV field is not closed.');
  if (cell || row.length || closed) pushRow();
  const header = rows.shift()?.map((value) => value.trim().toLowerCase());
  if (header?.length !== 2 || header[0] !== 'name' || header[1] !== 'domain')
    throw new Error('The first row must be name,domain.');
  if (!rows.length) throw new Error('The CSV contains no protected names.');
  return rows.map((row, i) => {
    if (row.length !== 2)
      throw new Error(`Record ${i + 1}: expected two columns.`);
    const entry = normalizeProtectedName({ name: row[0], domain: row[1] });
    const error = protectedNameError(entry);
    if (error) throw new Error(`Record ${i + 1}: ${error}`);
    return entry;
  });
}
export function previewIdentityImport(
  entries: ProtectedName[],
  existing: ProtectedName[],
) {
  const seen = new Set(
    existing.map((entry) => {
      const e = normalizeProtectedName(entry);
      return JSON.stringify([e.name.toLowerCase(), e.domain]);
    }),
  );
  const additions: ProtectedName[] = [];
  let duplicates = 0;
  for (const value of entries) {
    const entry = normalizeProtectedName(value),
      error = protectedNameError(entry);
    if (error) throw new Error(error);
    const key = JSON.stringify([entry.name.toLowerCase(), entry.domain]);
    if (seen.has(key)) duplicates++;
    else {
      seen.add(key);
      additions.push(entry);
    }
  }
  if (existing.length + additions.length > MAX_PROTECTED_NAMES)
    throw new Error(
      `This import would exceed the limit of ${MAX_PROTECTED_NAMES} protected names.`,
    );
  // This legacy detector evaluates each mapping independently. Do not imply that
  // two domains for the same display name create an alias/allowlist relationship.
  const conflicts = protectedNameConflicts([...existing, ...additions]);
  if (
    conflicts.some((name) =>
      additions.some((entry) => entry.name.toLowerCase() === name),
    )
  )
    throw new Error(
      'A name maps to more than one domain. Resolve the mapping before importing; multiple rows do not create an allowed-domain list.',
    );
  return { additions, duplicates };
}
