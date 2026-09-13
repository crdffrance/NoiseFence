export type ProviderQuota = { minute: number; day: number };
export type QuotaUsage = {
  minute_used: number;
  day_used: number;
  minute_resets_at: number;
  day_resets_at: number;
  cooldown_until: number | null;
};
export const quotaLabel = (quota: ProviderQuota) =>
  `${quota.minute === 0 ? "Unlimited" : quota.minute}/min · ${quota.day === 0 ? "Unlimited" : quota.day}/day`;
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
        Active limits: {applied ? quotaLabel(applied) : "module disabled"}
      </p>
      <label className="toggle-row">
        <span>
          Use installation defaults{' '}
          <small>{quotaLabel(bootstrap)}</small>
        </span>
        <input
          type="checkbox"
          checked={value == null}
          aria-label={`Installation defaults ${name}`}
          onChange={(e) => onChange(e.target.checked ? null : { ...bootstrap })}
        />
      </label>
      {value != null && (
        <>
          <button
            className="rounded-md border border-input bg-background px-3 py-2 text-sm font-medium shadow-xs hover:bg-accent focus-visible:outline-2"
            type="button"
            onClick={() => onChange({ minute: 0, day: 0 })}
          >
            Unlimited key — {name}
          </button>
          {(['minute', 'day'] as const).map((window) => {
            const label = window === 'minute' ? 'Per minute' : "Per day";
            return (
              <div className="form-grid" key={window}>
                <label className="field">
                  {label}
                  <input
                    className="w-full rounded-md border border-input bg-transparent px-3 py-2 shadow-xs focus-visible:outline-2 disabled:opacity-50"
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
                  <span>Unlimited</span>
                  <input
                    type="checkbox"
                    aria-label={`${name} ${label} unlimited`}
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
              Enter a positive integer or choose &quot;Unlimited&quot;.
            </p>
          )}
        </>
      )}
      <p className="small muted">
        Draft limits: {quotaLabel(quota)}. Use &quot;Review and apply&quot; to save.
      </p>
      {usage ? (
        <>
          <p className="small">
            Reserved requests: {usage.minute_used} this minute ·{' '}
            {usage.day_used} today (UTC). The cache does not consume quota.
          </p>
          <p className="small muted">
            Next reset: minute{' '}
            {new Date(usage.minute_resets_at * 1000).toLocaleTimeString(
              "en-GB",
            )}
            , day{' '}
            {new Date(usage.day_resets_at * 1000).toLocaleString("en-GB")}.
          </p>
          {usage.cooldown_until != null && (
            <output className="small">
              Provider cooldown until{' '}
              {new Date(usage.cooldown_until * 1000).toLocaleString("en-GB")}, including unlimited mode.
            </output>
          )}
        </>
      ) : (
        <p className="small muted">Usage counters unavailable.</p>
      )}
    </fieldset>
  );
}
