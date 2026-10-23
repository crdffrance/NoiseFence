'use client';
import { useEffect, useState } from 'react';
import { Button } from '@/components/ui/button';
import { api } from './client';
import { providerCredentialLabel } from './provider-credentials';
import { quotaLabel } from './provider-quotas';
import { CoverageDetails } from './coverage';
import { LlmPricingNotice } from './llm-pricing-notice';
import {
  stateLabel,
  detectorLabels,
  type ReliabilityReport,
} from './reliability-types';
import {
  euro,
  llmState,
  reputationState,
  type ProviderOverview,
} from './providers';

export type ProviderSettingsSection = 'protection' | 'parameters' | 'rbl';
const when = (t: number) => new Date(t * 1000).toLocaleString('en-GB');
type OverviewProps = {
  revision: number;
  hasDraft: boolean;
  onSettings: (section: ProviderSettingsSection) => void;
};
export function ProvidersOverview(props: OverviewProps) {
  return <ProviderSnapshot key={props.revision} {...props} />;
}
function ProviderSnapshot({ revision, hasDraft, onSettings }: OverviewProps) {
  const [reload, setReload] = useState(0);
  const [status, setStatus] = useState<ProviderOverview | null>(null);
  const [history, setHistory] = useState<ReliabilityReport | null>(null);
  const [statusError, setStatusError] = useState(''),
    [historyError, setHistoryError] = useState('');
  const [loadingStatus, setLoadingStatus] = useState(true),
    [loadingHistory, setLoadingHistory] = useState(true);
  const [scope, setScope] = useState('current');
  useEffect(() => {
    const controller = new AbortController();
    const options = { signal: controller.signal, cache: 'no-store' as const };
    api<ProviderOverview>('/admin/providers', undefined, undefined, options)
      .then((s) => {
        if (!controller.signal.aborted) setStatus(s);
      })
      .catch((e) => {
        if (!controller.signal.aborted)
          setStatusError(e.message || 'Provider configuration is unavailable.');
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoadingStatus(false);
      });
    api<ReliabilityReport>(
      '/quality/reliability?days=1',
      undefined,
      undefined,
      options,
    )
      .then((r) => {
        if (!controller.signal.aborted) setHistory(r);
      })
      .catch((e) => {
        if (!controller.signal.aborted)
          setHistoryError(e.message || 'Recorded checks are unavailable.');
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoadingHistory(false);
      });
    return () => controller.abort();
  }, [revision, reload]);
  function refresh() {
    setStatus(null);
    setHistory(null);
    setStatusError('');
    setHistoryError('');
    setLoadingStatus(true);
    setLoadingHistory(true);
    setReload((n) => n + 1);
  }
  const window =
    scope === 'current' ? history?.current_build_last_24h : history?.last_24h;
  const llm = status?.services.llm;
  return (
    <div className="providers-overview">
      <section className="panel">
        <div className="provider-heading">
          <div>
            <p className="eyebrow">OPERATIONS</p>
            <h2>Providers &amp; budgets</h2>
          </div>
          <Button
            type="button"
            disabled={loadingStatus || loadingHistory}
            onClick={refresh}
          >
            Refresh status
          </Button>
        </div>
        <p>
          Loaded settings, reserved quotas and recorded checks in one place.
          Refreshing this page does not contact a provider or send message
          content.
        </p>
        {hasDraft && (
          <p className="notice">
            You have unapplied changes. This view shows the loaded
            configuration; opening an editor preserves your draft.
          </p>
        )}
        {loadingStatus && <output>Reading provider configuration…</output>}
        {statusError && (
          <p role="alert" className="error">
            {statusError} No previous snapshot is presented as current.
          </p>
        )}
        {status && (
          <>
            <p className="muted small">
              {status.hostname}
              {status.node_id ? ` · ${status.node_id}` : ''} ·{' '}
              {status.cluster_role || 'standalone'} · loaded revision{' '}
              {status.revision} · captured {when(status.checked_at)}
            </p>
            {status.revision !== revision && (
              <p className="notice">
                The loaded revision has changed since this editor was opened.
                Reload configuration before applying your draft.
              </p>
            )}
            <p className="muted small">
              Counters belong to this node. On a coordinator they also include
              credits issued to other MX servers; do not add coordinator and
              worker counters together. Reserved amounts are not provider
              invoices or a count of successful lookups. Cluster synchronization
              and remaining local credits can further limit a worker.
            </p>
          </>
        )}
      </section>
      {status && (
        <div className="provider-cards">
          {(['crdf', 'virustotal'] as const).map((name) => {
            const usage = status.usage[name],
              quota = status.quotas?.[name];
            return (
              <section
                className="panel"
                key={name}
                aria-label={`${detectorLabels[name]} status`}
              >
                <h3>{name === 'crdf' ? 'CRDF Threat Center' : 'VirusTotal'}</h3>
                <p>
                  <strong>{reputationState(status, name)}</strong>
                </p>
                <p className="small">
                  {providerCredentialLabel(
                    status.keys[name],
                    status.loaded_keys?.[name],
                    status.pending_keys?.[name],
                  )}
                  . This does not verify the provider’s permissions or license.
                </p>
                <dl className="provider-facts">
                  <div>
                    <dt>Loaded limits</dt>
                    <dd>{quota ? quotaLabel(quota) : 'Module disabled'}</dd>
                  </div>
                  <div>
                    <dt>Reserved requests</dt>
                    <dd>
                      {usage
                        ? `${usage.minute_used} this minute · ${usage.day_used} today (UTC)`
                        : 'Unavailable'}
                    </dd>
                  </div>
                  {status.capacity && (
                    <div>
                      <dt>Analysis limits</dt>
                      <dd>
                        {status.capacity.timeout_ms} ms ·{' '}
                        {status.capacity.max_parallel} parallel · up to{' '}
                        {status.capacity.max_indicators} indicators/message
                      </dd>
                    </div>
                  )}
                </dl>
                {usage && (
                  <p className="small muted">
                    Next reset: minute {when(usage.minute_resets_at)}; day{' '}
                    {when(usage.day_resets_at)}. Cache hits do not consume
                    request quota.
                  </p>
                )}
                {usage?.cooldown_until != null && (
                  <p className="notice">
                    Cooldown until {when(usage.cooldown_until)}. Unlimited
                    quotas do not bypass provider backoff.
                  </p>
                )}
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => onSettings('protection')}
                >
                  Edit keys &amp; quotas
                </Button>
              </section>
            );
          })}
          {llm && (
            <section className="panel" aria-label="Scaleway status">
              <h3>Scaleway · LLM</h3>
              <p>
                <strong>{llmState(llm, status.checked_at)}</strong>
              </p>
              {llm.configuration && (
                <>
                  <dl className="provider-facts">
                    <div>
                      <dt>Loaded model</dt>
                      <dd>{llm.configuration.model}</dd>
                    </div>
                    <div>
                      <dt>Monthly policy ceiling</dt>
                      <dd>
                        {euro(llm.configuration.monthly_budget_micro_eur)}
                      </dd>
                    </div>
                    <div>
                      <dt>Content limit</dt>
                      <dd>
                        {llm.configuration.max_text_bytes.toLocaleString(
                          'en-GB',
                        )}{' '}
                        bytes of text/message
                      </dd>
                    </div>
                    <div>
                      <dt>Analysis limits</dt>
                      <dd>
                        {llm.configuration.timeout_ms} ms ·{' '}
                        {llm.configuration.max_parallel} parallel
                      </dd>
                    </div>
                    <div>
                      <dt>Selection</dt>
                      <dd>
                        Index {llm.configuration.score_low}–
                        {llm.configuration.score_high}
                        {llm.configuration.review_unconfirmed_high
                          ? ' and unconfirmed higher scores'
                          : ''}{' '}
                        · analysable messages only
                      </dd>
                    </div>
                  </dl>
                  <LlmPricingNotice
                    checkedAt={llm.configuration.pricing_checked_at}
                  />
                </>
              )}
              {llm.budget?.status === 'available' ? (
                <>
                  <dl className="provider-facts">
                    <div>
                      <dt>Accounted reservations · {llm.budget.month} UTC</dt>
                      <dd>{euro(llm.budget.accounted_micro_eur)}</dd>
                    </div>
                    <div>
                      <dt>Included credits issued to other MXs</dt>
                      <dd>{euro(llm.budget.issued_micro_eur)}</dd>
                    </div>
                    <div>
                      <dt>
                        {llm.budget.worker_wallet
                          ? 'Local credit ceiling'
                          : 'Effective ceiling'}
                      </dt>
                      <dd>{euro(llm.budget.ceiling_micro_eur)}</dd>
                    </div>
                    <div>
                      <dt>Unreserved allowance on this node</dt>
                      <dd>{euro(llm.budget.remaining_micro_eur)}</dd>
                    </div>
                    <div>
                      <dt>Local reservations</dt>
                      <dd>{llm.budget.requests}</dd>
                    </div>
                  </dl>
                  <p className="small muted">
                    Amounts include outstanding reservations and conservative
                    charges. They are not confirmed spend. Remote credits remain
                    reserved until window expiry.
                  </p>
                </>
              ) : (
                <p className="muted">
                  {llm.budget?.status === 'not_started'
                    ? 'No budget ledger exists on this node yet.'
                    : 'Budget ledger unavailable; spend is unknown.'}
                </p>
              )}
              <p className="small muted">
                Disabled policy and expired pricing verification remain in
                force. This page never renews the date, changes the model or
                enables analysis.
              </p>
              <Button
                type="button"
                variant="outline"
                onClick={() => onSettings('parameters')}
              >
                Edit LLM settings
              </Button>
            </section>
          )}
          <section className="panel" aria-label="RBL and comparison status">
            <h3>RBL &amp; independent comparison</h3>
            <dl className="provider-facts">
              <div>
                <dt>DNS blocklists</dt>
                <dd>
                  {status.services.rbl
                    ? `${status.services.rbl.enabled_lists} enabled lists · ${status.services.rbl.action}`
                    : 'Not configured'}
                </dd>
              </div>
              <div>
                <dt>Rspamd comparison</dt>
                <dd>
                  {status.services.rspamd?.enabled
                    ? `Enabled · ${status.services.rspamd.sample_percent}% sampling`
                    : 'Disabled'}
                </dd>
              </div>
            </dl>
            <p className="small muted">
              Configured RBL lists do not prove DNS availability or access
              rights. Rspamd records a separate opinion and never determines
              NoiseFence’s verdict or delivery.
            </p>
            <div className="provider-heading">
              <Button
                type="button"
                variant="outline"
                onClick={() => onSettings('rbl')}
              >
                Edit RBL settings
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={() => onSettings('parameters')}
              >
                Edit comparison settings
              </Button>
            </div>
          </section>
        </div>
      )}
      <section className="panel">
        <h2>Recorded checks · last 24 hours</h2>
        <p>
          Accessible message history may include several MX servers. It is
          separate from the node’s live counters above. A missing or failed
          check is neither evidence of spam nor proof of safety.
        </p>
        {loadingHistory && <output>Reading recorded checks…</output>}
        {historyError && (
          <p role="alert" className="error">
            {historyError}
          </p>
        )}
        {history && (
          <>
            <label className="field">
              Observation scope
              <select value={scope} onChange={(e) => setScope(e.target.value)}>
                <option value="current">Current engine build</option>
                <option value="all">All recorded builds</option>
              </select>
            </label>
            <p className="small muted">
              Captured {when(history.checked_at)} ·{' '}
              {history.status === 'limited' ? 'Partial history' : 'History'} ·{' '}
              {window?.messages ?? 0} matching messages. Old incidents do not
              necessarily describe the loaded revision.
            </p>
            {!window?.messages ? (
              <p>
                No matching observations. Availability and latency cannot be
                inferred.
              </p>
            ) : (
              <>
                <div className="reliability-table">
                  <table>
                    <caption>Recorded detector states</caption>
                    <thead>
                      <tr>
                        <th>Check</th>
                        <th>States and message counts</th>
                      </tr>
                    </thead>
                    <tbody>
                      {['crdf', 'virustotal', 'llm', 'redirects'].map(
                        (name) => (
                          <tr key={name}>
                            <th scope="row">
                              {name === 'llm'
                                ? 'Scaleway · LLM'
                                : detectorLabels[name]}
                            </th>
                            <td>
                              {Object.entries(
                                window.detector_status[name] ?? {},
                              )
                                .map(
                                  ([state, n]) => `${stateLabel(state)}: ${n}`,
                                )
                                .join(' · ') || 'Not recorded'}
                            </td>
                          </tr>
                        ),
                      )}
                    </tbody>
                  </table>
                </div>
                <CoverageDetails data={window.coverage} />
              </>
            )}
            {history.limitations.length > 0 && (
              <details>
                <summary>History scope and limitations</summary>
                <ul>
                  {history.limitations.map((text) => (
                    <li key={text}>{text}</li>
                  ))}
                </ul>
              </details>
            )}
          </>
        )}
      </section>
    </div>
  );
}
