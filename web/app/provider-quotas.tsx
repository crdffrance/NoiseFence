export type ProviderQuota = { minute: number; day: number };
export type QuotaUsage = {
  minute_used: number;
  day_used: number;
  minute_resets_at: number;
  day_resets_at: number;
  cooldown_until: number | null;
};
export const quotaLabel = (quota: ProviderQuota) =>
  `${quota.minute === 0 ? 'Illimité' : quota.minute}/min · ${quota.day === 0 ? 'Illimité' : quota.day}/jour`;
// Blank/invalid input must fail server validation, never imply unlimited.
export const numericQuota = (raw: string) =>
  raw.trim() &&
  Number.isInteger(Number(raw)) &&
  Number(raw) > 0 &&
  Number(raw) <= 4294967295
    ? Number(raw)
    : -1;
export function ProviderQuotas({
  name,
  value,
  bootstrap,
  applied,
  usage,
  onChange,
}: {
  name: string;
  value?: ProviderQuota | null;
  bootstrap: ProviderQuota;
  applied: ProviderQuota | null;
  usage?: QuotaUsage | null;
  onChange: (quota: ProviderQuota | null) => void;
}) {
  const quota = value ?? bootstrap;
  return (
    <fieldset className="module-card">
      <legend>Quotas {name}</legend>
      <p className="small muted">
        Actifs : {applied ? quotaLabel(applied) : 'module désactivé'}
      </p>
      <label className="toggle-row">
        <span>
          Utiliser les plafonds du serveur{' '}
          <small>{quotaLabel(bootstrap)}</small>
        </span>
        <input
          type="checkbox"
          checked={value == null}
          aria-label={`Plafonds du serveur ${name}`}
          onChange={(e) => onChange(e.target.checked ? null : { ...bootstrap })}
        />
      </label>
      {value != null && (
        <>
          <button
            className="secondary"
            type="button"
            onClick={() => onChange({ minute: 0, day: 0 })}
          >
            Clé illimitée — {name}
          </button>
          {(['minute', 'day'] as const).map((window) => {
            const label = window === 'minute' ? 'Par minute' : 'Par jour';
            return (
              <div className="form-grid" key={window}>
                <label className="field">
                  {label}
                  <input
                    className="input"
                    type="number"
                    min={1}
                    max={4294967295}
                    step={1}
                    aria-label={`${name} ${label}`}
                    disabled={quota[window] === 0}
                    value={quota[window] <= 0 ? '' : quota[window]}
                    onChange={(e) =>
                      onChange({
                        ...quota,
                        [window]: numericQuota(e.target.value),
                      })
                    }
                  />
                </label>
                <label className="toggle-row">
                  <span>Illimité</span>
                  <input
                    type="checkbox"
                    aria-label={`${name} ${label} illimité`}
                    checked={quota[window] === 0}
                    onChange={(e) =>
                      onChange({
                        ...quota,
                        [window]: e.target.checked ? 0 : bootstrap[window] || 1,
                      })
                    }
                  />
                </label>
              </div>
            );
          })}
          {(quota.minute < 0 || quota.day < 0) && (
            <p className="error" role="alert">
              Saisissez un entier positif ou choisissez « Illimité ».
            </p>
          )}
        </>
      )}
      <p className="small muted">
        À appliquer : {quotaLabel(quota)}. Utilisez « Vérifier et appliquer »
        pour enregistrer.
      </p>
      {usage ? (
        <>
          <p className="small">
            Requêtes réservées : {usage.minute_used} cette minute ·{' '}
            {usage.day_used} aujourd’hui (UTC). Le cache ne consomme pas de
            quota.
          </p>
          <p className="small muted">
            Prochaine remise à zéro : minute{' '}
            {new Date(usage.minute_resets_at * 1000).toLocaleTimeString(
              'fr-FR',
            )}
            , jour{' '}
            {new Date(usage.day_resets_at * 1000).toLocaleString('fr-FR')}.
          </p>
          {usage.cooldown_until != null && (
            <output className="small">
              Pause fournisseur jusqu’à{' '}
              {new Date(usage.cooldown_until * 1000).toLocaleString('fr-FR')}, y
              compris en mode illimité.
            </output>
          )}
        </>
      ) : (
        <p className="small muted">Compteurs indisponibles.</p>
      )}
    </fieldset>
  );
}
