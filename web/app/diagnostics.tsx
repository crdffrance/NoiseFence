'use client';
import { useEffect, useId, useRef, useState } from 'react';
import { RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { api } from './client';
import { observationState, observationRole, observationScope, observationName,
  observationResult, observationMeasurement, sharedObservationGroups,
  type ObservationReport } from './observations-format';
import {
  authenticationResult,
  contribution,
  deliveryStatus,
  duration,
  evidenceState,
  nextRetry,
  policySummary,
  smtpOutcome,
  smtpPhase,
  smtpReply,
  timestamp,
  transcriptNotice,
  recipientHistory,
  type AuthenticationEvidence,
  type DiagnosticReason,
  type DiagnosticRecipient,
  type RecipientHistory,
  type MessageDiagnostics,
  type SmtpLog,
} from './diagnostics-formatters';

function AuthenticationDetails({ auth }: { auth?: AuthenticationEvidence }) {
  return (
    <section
      className="diagnostic-section"
      aria-label="Authentication of the message"
    >
      <h3>SPF, DKIM, DMARC and ARC authentication</h3>
      {!auth ? (
        <p className="diagnostic-muted">
          No evidence of historical authentication recorded.
        </p>
      ) : (
        <>
          <p className="diagnostic-muted">
            SPF / DKIM / DMARC controls: {evidenceState(auth.state)}. ARC is controlled separately. An absent or unavailable check is not a successful result.
          </p>
          <dl className="diagnostic-facts diagnostic-auth">
            <div>
              <dt>SPF · {evidenceState(auth.spf_state)}</dt>
              <dd>{authenticationResult(auth.spf)}</dd>
            </div>
            <div>
              <dt>DKIM · {evidenceState(auth.dkim_state)}</dt>
              <dd>
                {auth.dkim == null ? (
                  "Result not recorded"
                ) : auth.dkim.length === 0 ? (
                  "No DKIM signature recorded"
                ) : (
                  <ul>
                    {auth.dkim.map((result, index) => (
                      <li key={index}>
                        Signature {index + 1} : {authenticationResult(result)}
                      </li>
                    ))}
                  </ul>
                )}
              </dd>
            </div>
            <div>
              <dt>DMARC · {evidenceState(auth.dmarc_state)}</dt>
              <dd>
                SPF alignment: {authenticationResult(auth.dmarc_spf)}
                <br />
                DKIM alignment: {authenticationResult(auth.dmarc_dkim)}
              </dd>
            </div>
            <div>
              <dt>ARC · {evidenceState(auth.arc_state)}</dt>
              <dd>
                {authenticationResult(auth.arc)}
                <br />
                {auth.arc_can_seal == null
                  ? "Sealing capability not recorded"
                  : auth.arc_can_seal
                    ? "Sealing available"
                    : "Sealing not possible"}
              </dd>
            </div>
          </dl>
        </>
      )}
    </section>
  );
}

function DetectorObservations({ report }: { report?: ObservationReport | null }) {
  if (!report) return <p className="diagnostic-muted">Normalized detector observations were not recorded for this message.</p>;
  const shared = sharedObservationGroups(report);
  return <details className="diagnostic-disclosure">
    <summary>Detector availability and recorded results</summary>
    <p className="diagnostic-muted">Receipt-time observations. A completed request is not proof of safety. Missing, disabled and excluded results are not votes. Comparison and admission checks do not add to the content score.</p>
    <section className="diagnostic-observations-scroll" aria-label="Recorded detector observations">
      <table className="diagnostic-table">
        <caption>Detector results · schema {report.version}</caption>
        <thead><tr><th scope="col">Detector / scope</th><th scope="col">Availability / role</th><th scope="col">Result / original units</th></tr></thead>
        <tbody>{report.observations.map(o => <tr key={o.id}>
          <th scope="row">{observationName(o.id)}<div className="diagnostic-muted">{observationScope(o.scope)}</div>
            {o.version && <div className="diagnostic-muted">{o.version}</div>}</th>
          <td>{observationState(o.state)}<div className="diagnostic-muted">{observationRole(o.role)}</div>
            {o.elapsed_ms != null && <div className="diagnostic-muted">{duration(o.elapsed_ms)}</div>}</td>
          <td>{observationResult(o)}{Object.entries(o.measurements).map(([name,m]) =>
            <div key={name} className="diagnostic-muted">{observationMeasurement(name,m)}</div>)}
            {o.queried_at != null && <div className="diagnostic-muted">Lookup recorded {timestamp(o.queried_at)}
              {o.cache_max_age_seconds != null && ` · cache age at lookup ≤ ${o.cache_max_age_seconds} s`}
              {o.analysis_max_age_seconds != null ? ` · provider analysis age ≤ ${o.analysis_max_age_seconds} s` : ' · provider analysis age not attested'}</div>}
          </td>
        </tr>)}</tbody>
      </table>
    </section>
    {shared.length > 0 && <details><summary>Shared evidence across observations</summary>
      <p className="diagnostic-muted">These observations share a target or content family. They are not independent confirmations. Grouping documents correlations; it does not itself change the recorded score.</p>
      <ul>{shared.map(g => <li key={g.key}>{g.observations.map(observationName).join(' · ')}{g.conflict && ' — conflicting reputation results'}</li>)}</ul>
    </details>}
    {report.omitted > 0 && <p className="diagnostic-muted">Bounded detail: {report.omitted} target or observation entries omitted.</p>}
  </details>;
}

function AnalysisDetails({
  analysis,
  reasons,
  source,
}: {
  analysis: MessageDiagnostics['analysis'];
  reasons: DiagnosticReason[];
  source?: string;
}) {
  const overrides = Object.entries(analysis.policy?.rule_weights ?? {}).filter(
    ([id]) => reasons.some((reason) => reason.id === id),
  );
  return (
    <section
      className="diagnostic-section"
      aria-label="Analysis recorded at receipt"
    >
      <h3>Analysis recorded at receipt</h3>
      <dl className="diagnostic-facts">
        <div>
          <dt>Total duration of analysis</dt>
          <dd>{duration(analysis.elapsed_ms)}</dd>
        </div>
        <div>
          <dt>Extraction version</dt>
          <dd>{analysis.feature_version}</dd>
        </div>
        <div>
          <dt>Feature extraction</dt>
          <dd>
            {analysis.features_complete == null
              ? "Historical completion not recorded"
              : analysis.features_complete
                ? "Complete"
                : "Partial"}
          </dd>
        </div>
      </dl>
      <p className="diagnostic-callout">{policySummary(analysis.policy)}</p>
      <DetectorObservations report={analysis.observations} />
      {analysis.policy && (
        <p className="diagnostic-muted">
          Policy version: <code>{analysis.policy.version}</code>.
          {source === 'fusion' &&
            " This threshold belongs to the historical calculation, not to the fusion model."}
          {source === 'antivirus' &&
            " The antivirus priority does not depend on this threshold."}
        </p>
      )}
      <dl className="diagnostic-facts">
        <div>
          <dt>lexical · log-odds model</dt>
          <dd>{contribution(analysis.lexical_logit)}</dd>
          <dd className="diagnostic-muted">
            {evidenceState(analysis.evidence?.lexical_state)}
          </dd>
        </div>
        <div>
          <dt>Semantic contribution · log-odds</dt>
          <dd>{contribution(analysis.semantic_contribution)}</dd>
          <dd className="diagnostic-muted">
            {evidenceState(analysis.evidence?.semantic_state)}
          </dd>
        </div>
        <div>
          <dt>Total weight of rules · log-odds</dt>
          <dd>{contribution(analysis.rule_weight_total)}</dd>
        </div>
      </dl>
      <p className="diagnostic-muted">
        Recorded contributions before conversion to a score. They are not percentages, do not sum to 100 and may be correlated. An unrecorded contribution is not zero.
      </p>
      {analysis.score_breakdown && <details className="diagnostic-disclosure">
        <summary>Contributions by control family</summary>
        <dl className="diagnostic-facts">{Object.entries(analysis.score_breakdown.families).map(([family,value])=><div key={family}>
          <dt>{({lexical:"Text and structure",semantic:"Semantic analysis",content_unseparated:"Content, historical detail absent",heuristics:"Content rules",authentication:"Authentication",reputation:"Reputation",smtp:"SMTP controls",llm:"Second opinion",other_rules:"Other rules",rules_baseline:"Fixed partial-index baseline (not learned)"} as Record<string,string>)[family] ?? "Other contributions"}</dt><dd>{contribution(value)}</dd>
        </div>)}</dl>
        <p className="diagnostic-muted">{analysis.score_breakdown.matches_recorded_score ? "The sum reproduces the recorded historical score." : "The observations retained are not sufficient to accurately reproduce the historical score."}
          {analysis.score_breakdown.saturated && " The index is close to one end; it is not proof of certainty."}</p>
      </details>}
      {analysis.native_filter && <details className="diagnostic-disclosure">
        <summary>Native engine: composite rules, campaigns and Bayes</summary>
        <p className="diagnostic-muted">Comparative observation without effect on delivery. Points and result Bayes are not calibrated probabilities.</p>
        <dl className="diagnostic-facts">
          <div><dt>Local analysis</dt><dd>{evidenceState(analysis.native_filter.status)} · {duration(analysis.native_filter.elapsed_ms)}</dd></div>
          <div><dt>Points after ceilings</dt><dd>{contribution(analysis.native_filter.score?.total)}</dd></div>
          <div><dt>OSB Bayes Classifier</dt><dd>{({untrained:"No model trained",complete:"Analysis available",scope_mismatch:"Domain outside model scope",expired:"Model expired",insufficient_features:"Insufficient evidence",incompatible:"incompatible protocol"} as Record<string,string>)[analysis.native_filter.bayes.status] ?? "Analysis not available"}</dd></div>
          <div><dt>Campaign memory</dt><dd>{evidenceState(analysis.native_filter.fuzzy.status)} · {analysis.native_filter.fuzzy.matches} text correspondence(s)
            {analysis.native_filter.fuzzy.conflict && " · conflicting corrections, no reinforcement"}</dd></div>
        </dl>
        {analysis.native_filter.score && <>
          <table className="diagnostic-table"><caption>Consolidated contributions</caption><thead><tr><th>Family</th><th>Raw</th><th>Retained</th></tr></thead>
            <tbody>{Object.entries(analysis.native_filter.score.families).map(([family,weight])=><tr key={family}><td>{({lexical:"Text and structure",semantic:"Semantics",content:"Content rules",authentication:"Authentication",reputation:"Reputation",smtp:'SMTP',llm:"Second opinion",campaign:"Campaigns",bayes:'OSB Bayes',other:"Other"} as Record<string,string>)[family] ?? family}</td><td>{contribution(weight.raw)}</td><td>{contribution(weight.effective)}{weight.capped && " · capped"}</td></tr>)}</tbody>
          </table>
          <ul>{analysis.native_filter.score.symbols.map(symbol=><li key={symbol.id}><code>{symbol.id}</code> · {symbol.label} · {contribution(symbol.weight)}
            {symbol.absorbed_by.length>0 && ` · grouped in ${symbol.absorbed_by.join(', ')}`}</li>)}</ul>
        </>}
      </details>}
      {overrides.length > 0 && (
        <details className="diagnostic-disclosure">
          <summary>
            Custom weight recorded for triggered rules
          </summary>
          <dl className="diagnostic-facts">
            {overrides.map(([id, weight]) => (
              <div key={id}>
                <dt>
                  <code>{id}</code>
                </dt>
                <dd>{contribution(weight)} log-odds</dd>
              </div>
            ))}
          </dl>
        </details>
      )}
    </section>
  );
}

function SmtpAttempt({ log, latest }: { log: SmtpLog; latest: boolean }) {
  return (
    <details
      className="diagnostic-disclosure smtp-attempt"
      open={latest ? true : undefined}
    >
      <summary>
        <span>
          Attempt {log.attempt} · {smtpOutcome(log.outcome)}
        </span>
        <span className="diagnostic-muted">
          {timestamp(log.started)} · {duration(log.elapsed_ms)}
        </span>
      </summary>
      <dl className="diagnostic-facts">
        <div>
          <dt>SMTP route</dt>
          <dd>{log.route || "Unrecorded route"}</dd>
        </div>
        <div>
          <dt>Connected server (peer)</dt>
          <dd>{log.peer || "Peer not recorded"}</dd>
        </div>
      </dl>
      {log.truncated && (
        <p className="diagnostic-callout">
          Truncated log: steps or replies may be missing.
        </p>
      )}
      {log.events.length ? (
        <ol
          className="smtp-timeline"
          aria-label={`SMTP exchanges for attempt ${log.attempt}`}
        >
          {log.events.map((event, index) => (
            <li key={index}>
              <div className="smtp-event-heading">
                <strong>{smtpPhase(event.phase)}</strong>
                <span className="diagnostic-muted">
                  + {duration(event.elapsed_ms)} from the beginning
                </span>
              </div>
              {(event.code != null || event.enhanced_code) && (
                <p className="smtp-reply-code">
                  {smtpReply(event.code, event.enhanced_code)}
                </p>
              )}
              {event.response && (
                <p className="smtp-response">{event.response}</p>
              )}
              {event.detail && (
                <p className="smtp-response diagnostic-muted">{event.detail}</p>
              )}
              {event.code == null && !event.response && !event.detail && (
                <p className="diagnostic-muted">
                  No detailed response recorded.
                </p>
              )}
            </li>
          ))}
        </ol>
      ) : (
        <p className="diagnostic-muted">
          No detailed SMTP steps recorded for this attempt.
        </p>
      )}
    </details>
  );
}

function RecipientDetails({
  recipient,
  messageId,
  refreshing,
  refreshSignal,
  onRecipientLoaded,
}: {
  recipient: DiagnosticRecipient;
  messageId: string;
  refreshing: boolean;
  refreshSignal: AbortSignal;
  onRecipientLoaded: (
    messageId: string,
    recipient: DiagnosticRecipient,
  ) => void;
}) {
  const headingId = useId();
  const historyRequest = useRef<AbortController | null>(null);
  const [history, setHistory] = useState<{
    data: RecipientHistory | null;
    loading: boolean;
    error: string;
  }>({ data: null, loading: false, error: '' });
  useEffect(() => () => historyRequest.current?.abort(), []);
  async function loadHistory() {
    if (refreshing || refreshSignal.aborted) return;
    historyRequest.current?.abort();
    const controller = new AbortController();
    historyRequest.current = controller;
    const abort = () => controller.abort();
    refreshSignal.addEventListener('abort', abort, { once: true });
    setHistory((previous) => ({ ...previous, loading: true, error: '' }));
    try {
      const data = await api<MessageDiagnostics>(
        `/messages/${encodeURIComponent(messageId)}/diagnostics?delivery_id=${encodeURIComponent(recipient.delivery_id)}`,
        undefined,
        undefined,
        { signal: controller.signal, cache: 'no-store' },
      );
      const updated = recipientHistory(
        data,
        messageId,
        recipient.delivery_id,
        controller.signal,
      );
      if (!updated) return;
      setHistory({
        data: updated,
        loading: false,
        error: '',
      });
      onRecipientLoaded(messageId, updated);
    } catch (error: unknown) {
      if (controller.signal.aborted) return;
      setHistory((previous) => ({
        ...previous,
        loading: false,
        error:
          error instanceof Error
            ? error.message
            : "The loading of history failed.",
      }));
    } finally {
      refreshSignal.removeEventListener('abort', abort);
    }
  }
  const displayedHistory = history.data ?? recipient;
  // The API caps logs per recipient. Preserve event order inside each attempt.
  const logs = [...displayedHistory.logs].sort(
    (a, b) => b.started - a.started || b.id - a.id,
  );
  return (
    <section className="diagnostic-recipient" aria-labelledby={headingId}>
      <h4 id={headingId}>{recipient.address}</h4>
      <p className="diagnostic-delivery-state">
        {deliveryStatus(displayedHistory.status)}
      </p>
      <dl className="diagnostic-facts">
        <div>
          <dt>Delivery destination</dt>
          <dd>{displayedHistory.destination || "Not recorded"}</dd>
        </div>
        <div>
          <dt>Attempts made</dt>
          <dd>{displayedHistory.attempts}</dd>
        </div>
      </dl>
      <p>{nextRetry(displayedHistory.status, displayedHistory.next_attempt)}</p>
      {displayedHistory.last_error && (
        <div className="diagnostic-callout">
          <strong>Last recorded error</strong>
          <p className="smtp-response">{displayedHistory.last_error}</p>
        </div>
      )}
      <p className="diagnostic-muted">
        {transcriptNotice(
          logs.length,
          displayedHistory.logs_available,
          displayedHistory.logs_truncated,
        )}
      </p>
      {(recipient.logs_truncated ||
        recipient.logs_available > recipient.logs.length ||
        history.data) && (
        <div className="diagnostic-history-controls">
          <Button
            variant="outline"
            disabled={history.loading || refreshing}
            onClick={() => void loadHistory()}
            aria-label={`${history.error ? "Retry loading of" : history.data ? "Refresh" : "Load"} the historical SMTP of ${recipient.address}`}
          >
            <RefreshCw
              size={16}
              aria-hidden="true"
              className={history.loading ? 'spin' : ''}
            />
            {history.loading
              ? "Loading history..."
              : history.error
                ? "Retry"
                : history.data
                  ? "Updating SMTP history"
                  : "Load SMTP history"}
          </Button>
          <p className="diagnostic-muted">
            Up to 50 recent logs for this recipient. Refresh all to return to the combined view.
          </p>
        </div>
      )}
      <output className="diagnostic-muted diagnostic-loading-status">
        {history.loading
          ? "Loading this recipient’s logs…"
          : history.data && !history.error
            ? "History of this updated recipient."
            : ''}
      </output>
      {history.error && (
        <div className="diagnostic-callout" role="alert">
          <p>History not available: {history.error}</p>
          <p>Previously loaded logs remain visible.</p>
        </div>
      )}
      <div aria-busy={history.loading}>
        {logs.map((log, index) => (
          <SmtpAttempt key={log.id} log={log} latest={index === 0} />
        ))}
      </div>
    </section>
  );
}

export default function Diagnostics({
  messageId,
  reasons,
  source,
  revision,
  onLoaded,
  onRecipientLoaded,
}: {
  messageId: string;
  reasons: DiagnosticReason[];
  source?: string;
  revision: number;
  onLoaded: (diagnostics: MessageDiagnostics) => void;
  onRecipientLoaded: (
    messageId: string,
    recipient: DiagnosticRecipient,
  ) => void;
}) {
  const titleId = useId();
  // Abort scoped work immediately when global refresh starts, before React's
  // keyed recipient cleanup. Recipient unmounts also cancel their own requests.
  const [{ request, scope: refreshScope }, setRefresh] = useState(() => ({
    request: 0,
    scope: new AbortController(),
  }));
  const [state, setState] = useState<{
    messageId: string;
    data: MessageDiagnostics | null;
    request: number;
    revision: number;
    error: string;
    updated: number | null;
  }>({
    messageId,
    data: null,
    request: -1,
    revision: -1,
    error: '',
    updated: null,
  });
  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    api<MessageDiagnostics>(
      `/messages/${encodeURIComponent(messageId)}/diagnostics`,
      undefined,
      undefined,
      { signal: controller.signal, cache: 'no-store' },
    )
      .then((data) => {
        if (!active) return;
        if (data.message_id !== messageId)
          throw new Error(
            "The diagnosis received does not correspond to the selected message.",
          );
        setState({
          messageId,
          data,
          request,
          revision,
          error: '',
          updated: Date.now() / 1000,
        });
        onLoaded(data);
      })
      .catch((error: unknown) => {
        if (!active) return;
        setState((previous) => ({
          messageId,
          data: previous.messageId === messageId ? previous.data : null,
          updated: previous.messageId === messageId ? previous.updated : null,
          request,
          revision,
          error:
            error instanceof Error
              ? error.message
              : "The loading of diagnostics failed.",
        }));
      });
    return () => {
      active = false;
      controller.abort();
    };
  }, [messageId, request, revision, onLoaded]);
  // Never show the previous message, even before the new selection's effect runs.
  const visible = state.messageId === messageId ? state : null;
  const loading =
    !visible || visible.request !== request || visible.revision !== revision;
  const error = loading ? '' : visible?.error;
  const data = visible?.data;
  return (
    <section className="panel message-diagnostics" aria-labelledby={titleId}>
      <div className="diagnostic-heading">
        <h2 id={titleId}>Message diagnostics</h2>
        <Button
          variant="outline"
          disabled={loading}
          onClick={() => {
            refreshScope.abort();
            setRefresh((previous) => ({
              request: previous.request + 1,
              scope: new AbortController(),
            }));
          }}
        >
          <RefreshCw
            size={16}
            aria-hidden="true"
            className={loading ? 'spin' : ''}
          />
          {loading
            ? "Loading…"
            : error
              ? "Retry"
              : "Update diagnostics"}
        </Button>
      </div>
      <p className="diagnostic-queue-id">
        <span className="diagnostic-muted">Queue ID: </span>
        <code>{messageId}</code>
      </p>
      <output className="diagnostic-muted diagnostic-loading-status">
        {loading
          ? data
            ? "Updating SMTP attempts... The latest data received remains on display."
            : "Loading analysis and SMTP logs..."
          : visible?.updated
            ? `Last updated: ${timestamp(visible.updated)}.`
            : ''}
      </output>
      {error && (
        <div className="diagnostic-callout" role="alert">
          <p>Diagnostics not available: {error}</p>
          {data && (
            <p>
              The data displayed is from the last successful reading; delivery may have evolved.
            </p>
          )}
        </div>
      )}
      <div aria-busy={loading}>
        {data && (
          <>
            <AnalysisDetails
              analysis={data.analysis}
              reasons={reasons}
              source={source}
            />
            <AuthenticationDetails
              auth={data.analysis.evidence?.authentication}
            />
            <section
              className="diagnostic-section"
              aria-label="SMTP transmission per recipient"
            >
              <h3>SMTP transmission per recipient</h3>
              <p className="diagnostic-callout">
                &quot;Accepted&quot; means that the recipient server accepted the message after its transfer. This does not guarantee its arrival in the inbox: the provider can still filter or classify it.
              </p>
              <p className="diagnostic-muted">
                Only authorized recipients are displayed. Refresh to follow new attempts.
              </p>
              {data.recipients.length ? (
                data.recipients.map((recipient) => (
                  <RecipientDetails
                    // A global refresh discards scoped histories and cancels their in-flight requests.
                    key={`${messageId}:${recipient.delivery_id}:${request}:${revision}`}
                    recipient={recipient}
                    messageId={messageId}
                    refreshing={loading}
                    refreshSignal={refreshScope.signal}
                    onRecipientLoaded={onRecipientLoaded}
                  />
                ))
              ) : (
                <p>No authorized recipients available for this message.</p>
              )}
            </section>
          </>
        )}
      </div>
    </section>
  );
}
