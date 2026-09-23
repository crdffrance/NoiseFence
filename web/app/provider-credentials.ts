// Saved source files and credentials captured by the current configuration are
// distinct. Older API responses must not be presented as confirmed activation.
export function providerCredentialLabel(
  saved: boolean,
  loaded?: boolean,
  pending?: boolean,
) {
  if (pending) return 'Key change not applied to the current configuration';
  if (loaded) return 'Key captured by the current configuration';
  return saved ? 'Saved key · apply settings to load' : 'Key required';
}
export function providerToggleDisabled(
  saved: boolean,
  loaded: boolean | undefined,
  enabled: boolean,
) {
  return !saved && !loaded && !enabled;
}

export function keySaveNotice(result: {
  staged?: boolean;
  active?: boolean;
  message?: string;
}) {
  if (result.staged)
    return 'Key change submitted for coordinated activation. It is not applied until every MX is ready.';
  if (result.active)
    return 'Key loaded into the configuration for future analyses.';
  return (
    result.message ?? 'Key saved on the server. Apply settings to load it.'
  );
}
