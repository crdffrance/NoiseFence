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
