import type { CustomPolicy, Profile } from './custom-filtering';
import type { ActionPolicy } from './actions';

export type SensitivityLevel = {
  id: string;
  label: string;
  threshold: number;
  description: string;
};

export function scopedProfile(
  policy: CustomPolicy | null | undefined,
  scope: string,
) {
  const binding = policy?.bindings.find((b) => b.scope === scope);
  return policy?.profiles.find((p) => p.id === binding?.profile);
}

export function levelValue(
  threshold: number | null,
  levels: SensitivityLevel[],
) {
  return threshold === null
    ? 'inherit'
    : (levels.find((l) => l.threshold === threshold)?.id ?? 'custom');
}

export function sensitivityChanges(
  before: CustomPolicy | null | undefined,
  after: CustomPolicy | null | undefined,
) {
  const scopes = new Set(
    [...(before?.bindings ?? []), ...(after?.bindings ?? [])].map(
      (b) => b.scope,
    ),
  );
  return [...scopes]
    .map((scope) => ({
      scope,
      before: scopedProfile(before, scope)?.threshold ?? null,
      after: scopedProfile(after, scope)?.threshold ?? null,
    }))
    .filter((c) => c.before !== c.after);
}

/** Copy a shared profile before changing one scope; never change delivery actions. */
export function setScopeThreshold(
  policy: CustomPolicy | null | undefined,
  scope: string,
  threshold: number | null,
  actions: ActionPolicy,
  newId: () => string = () => crypto.randomUUID(),
): CustomPolicy | null {
  if (
    threshold !== null &&
    (!Number.isFinite(threshold) || threshold < 50 || threshold > 100)
  ) {
    throw new Error('Le seuil doit être compris entre 50 et 100.');
  }
  const p = policy ?? { profiles: [], bindings: [], rules: [] };
  const current = scopedProfile(p, scope);
  if (!current && threshold === null) return policy ?? null;
  const shared =
    current &&
    p.bindings.some((b) => b.profile === current.id && b.scope !== scope);
  if ((!current || shared) && p.profiles.length >= 32)
    throw new Error('Maximum de 32 profils atteint.');
  if (!current && p.bindings.length >= 1000)
    throw new Error('Maximum de 1 000 affectations atteint.');
  const inherited =
    current ?? (scope !== '*' ? scopedProfile(p, '*') : undefined);
  const profile: Profile = {
    ...(inherited ?? {
      spam: actions.spam,
      publicity: actions.publicity,
      review: 'deliver',
      quarantine_days: actions.quarantine_days,
      require_corroboration: true,
    }),
    id: current && !shared ? current.id : newId(),
    name:
      current && !shared
        ? current.name
        : scope === '*'
          ? 'Organisation'
          : `Domaine ${scope.slice(2)}`.slice(0, 100),
    threshold,
    require_corroboration:
      threshold !== null || (inherited?.require_corroboration ?? true),
  };
  return {
    ...p,
    profiles:
      current && !shared
        ? p.profiles.map((v) => (v.id === current.id ? profile : v))
        : [...p.profiles, profile],
    bindings: current
      ? p.bindings.map((b) =>
          b.scope === scope ? { ...b, profile: profile.id } : b,
        )
      : [...p.bindings, { scope, profile: profile.id }],
  };
}
