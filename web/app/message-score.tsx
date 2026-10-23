import {
  coveragePresentation,
  receiptAssessment,
  receiptDecision,
} from './assessment';
import { actionReason } from './action-coverage';
import { ActionCoverageDetails } from './action-coverage-view';
import { PolicyTraceDetails } from './policy-trace-view';
import { ScoreMeter } from './brand';
import { deliverySummary, scorePresentation, type ScoreInput } from './presentation';
import {
  ShieldAlert,
  ShieldCheck,
  Mail,
  Shield,
  ArrowRight,
  ScanLine,
} from 'lucide-react';

export function MessageScore({
  mail,
  tone,
}: {
  mail: ScoreInput;
  tone?: string;
}) {
  const score = scorePresentation(mail);
  return (
    <span className={`message-score ${score.kind}`} title={score.detail}>
      <ScoreMeter
        score={score.value}
        tone={tone}
        label={`${score.label} out of 100`}
      />
      <span className="score-caption">{score.label}</span>
    </span>
  );
}

export function MessageScoreDetails({
  mail,
  recipients,
  verdict,
}: {
  mail: ScoreInput;
  recipients?: { status: string }[];
  verdict?: { label: string; tone: string };
}) {
  const score = scorePresentation(mail);
  const coverage = coveragePresentation(mail);
  const assessment = receiptAssessment(mail);
  const record = receiptDecision(mail);
  const boundary =
    assessment?.score_boundary?.version === 1
      ? assessment.score_boundary
      : null;
  const fusionScore =
    assessment?.score.source === 'decision' &&
    assessment.decision.source === 'fusion';
  const category = assessment?.category;
  const shown =
    verdict ??
    (category === 'spam'
      ? { label: 'Spam', tone: 'spam' }
      : category === 'publicity'
        ? { label: 'Pub', tone: 'publicity' }
        : category === 'legitimate'
          ? { label: 'Ham', tone: 'good' }
          : { label: 'Not recorded', tone: 'neutral' });
  const action = assessment?.action;
  const delivery = recipients ? deliverySummary(recipients) : null;
  const actions: Record<string, string> = {
    deliver: 'Deliver',
    tag: 'Tag and deliver',
    quarantine: 'Quarantine',
  };
  const coverageTone =
    coverage.complete && !coverage.hasGaps ? 'good' : 'review';
  const guard = assessment?.score_resolution?.guard;
  const Icon =
    shown.tone === 'spam'
      ? ShieldAlert
      : shown.tone === 'publicity'
        ? Mail
        : shown.tone === 'good'
          ? ShieldCheck
          : Shield;
  const basis =
    assessment?.classification_source === 'recipient_policy'
      ? 'Recipient policy applied'
      : guard === 'authenticated_benign_conflict'
        ? 'Accepted by the contextual safeguard'
        : guard === 'corroboration_required'
          ? 'Accepted because corroboration is missing'
          : assessment?.decision.source === 'antivirus'
            ? 'Malware protection takes priority'
            : 'NoiseFence’s independent decision';
  const explanation =
    assessment?.classification_source === 'recipient_policy'
      ? 'The recipient’s recorded rules determine this category. Engine evidence remains available below.'
      : guard === 'authenticated_benign_conflict'
        ? 'Authenticated benign context takes precedence over the content index. The high index remains visible for diagnosis.'
        : guard === 'corroboration_required'
          ? 'The content index cannot confirm itself. This acceptance is a policy decision, not proof that the message is safe.'
          : shown.label === 'Spam'
            ? 'Classified as unwanted. The recorded delivery policy determines whether it is delivered, tagged or held.'
            : shown.label === 'Pub'
              ? 'Classified as an advertisement or newsletter. Delivery follows the recipient’s policy.'
              : shown.label === 'Ham'
                ? 'Accepted by the recorded filtering policy. Available evidence and analysis limitations are shown below.'
                : 'No classification was recorded for this historical message.';
  return (
    <div className={`message-score-details ${score.kind}`}>
      <div className={`verdict-banner ${shown.tone}`}>
        <span className="verdict-icon">
          <Icon size={28} aria-hidden="true" />
        </span>
        <div className="verdict-copy">
          <span className="analysis-stat-label">NoiseFence verdict</span>
          <div className="verdict-title">
            <h3>{shown.label}</h3>
            <span>{basis}</span>
          </div>
          <p>{explanation}</p>
        </div>
        <span className="verdict-record">
          {assessment?.score_resolution?.projected ||
          assessment?.classification_source === 'historical_fallback'
            ? 'Historical projection'
            : record
              ? 'Saved at receipt'
              : 'Recorded analysis'}
        </span>
      </div>
      <dl className={`analysis-overview ${delivery ? 'with-delivery' : ''}`} aria-label="NoiseFence verdict and delivery summary">
        <div className="analysis-stat">
          <dt className="analysis-stat-label">{score.label}</dt>
          <dd className="score-large">
            {score.value?.toFixed(1) ?? '—'}
            {score.value !== null && <span>/ 100</span>}
          </dd>
          {score.value !== null && (
            <dd className="analysis-meter">
              <meter
                min={0}
                max={100}
                value={score.value}
                aria-label={`${score.label}, not a spam probability`}
              />
            </dd>
          )}
          <dd className="analysis-stat-note">
            {score.value === null
              ? 'No usable value recorded'
              : score.kind === 'internal'
                ? 'Internal value, not an incoming scan'
                : 'Risk index, not a probability'}
          </dd>
        </div>
        <div className="analysis-stat">
          <dt className="analysis-stat-label">
            <ScanLine size={14} aria-hidden="true" /> Analysis coverage
          </dt>
          <dd className={`status ${coverageTone}`}>{coverage.label}</dd>
          <dd className="analysis-stat-note">
            Coverage is separate from the verdict
          </dd>
        </div>
        <div className="analysis-stat">
          <dt className="analysis-stat-label">
            <ArrowRight size={14} aria-hidden="true" /> Action at receipt
          </dt>
          <dd className="analysis-action-value">
            {action
              ? (actions[action.effective] ?? 'Not recorded')
              : 'Not recorded'}
          </dd>
          <dd className="analysis-stat-note">
            {assessment?.mode === 'observe'
              ? 'Observation mode'
              : 'Recorded policy'}{' '}
            · not delivery confirmation
          </dd>
        </div>
        {delivery && <div className="analysis-stat">
          <dt className="analysis-stat-label">Last recorded delivery</dt>
          <dd className={`status ${delivery.tone}`}>{delivery.label}</dd>
          <dd className="analysis-stat-note">Authorized recipients only · not an inbox guarantee</dd>
        </div>}
      </dl>
      <p className="analysis-summary-note">
        {action ? actionReason(action.reason) + '. ' : ''}
        {coverage.detail}
      </p>
      <details className="analysis-explanation">
        <summary>Decision basis, score boundary and policy</summary>
        <p className="score-label">
          <strong>{score.label}</strong>
          {score.model && <span> · {score.model}</span>}
        </p>
        <p className="score-explanation">{score.detail}</p>
        <div className="assessment-facts">
          <span title={coverage.detail} className={`status ${coverageTone}`}>
            {coverage.label}
          </span>
          {boundary ? (
            <span>
              Recorded score boundary:{' '}
              <strong>
                {boundary.cutoff}{' '}
                {boundary.source === 'fusion' ? 'logit' : '/ 100'}
              </strong>
            </span>
          ) : fusionScore ? (
            <span>Fusion boundary not recorded</span>
          ) : (
            assessment?.content_threshold != null && (
              <span>
                Recorded content threshold:{' '}
                <strong>{assessment.content_threshold} / 100</strong>
              </span>
            )
          )}
          {assessment?.classification_source === 'historical_fallback' && (
            <span>
              {assessment.content_threshold == null
                ? 'Original policy not recorded'
                : 'Historical classification reconstructed'}
            </span>
          )}
          {record && (
            <span>
              Receipt policy:{' '}
              <code title={record.policy_sha256}>
                {record.policy_sha256.slice(0, 12)}
              </code>
            </span>
          )}
          {record?.profile && (
            <span>
              Profile: <strong>{record.profile}</strong>
            </span>
          )}
        </div>
        {boundary && (
          <p className="score-explanation">
            {boundary.source === 'fusion' ? (
              <>
                Fusion compares its native logit ({boundary.value}) with the
                recorded cutoff ({boundary.cutoff}). Mapped boundary:{' '}
                {boundary.index_cutoff} / 100. The native comparison applies
                even when displayed scores round to the same value.{' '}
              </>
            ) : (
              <>
                The content index is compared with the recorded content
                threshold.{' '}
              </>
            )}
            Comparison: {boundary.above ? 'at or above' : 'below'} the boundary.
            Evidence, recipient rules and delivery restrictions can take
            precedence.
          </p>
        )}
        {record && assessment?.action && (
          <>
            <p className="score-explanation">
              Requested action: {assessment.action.requested}. Effective action:{' '}
              {assessment.action.effective}.{' '}
              {actionReason(assessment.action.reason)}. This decision is
              preserved when settings change.
            </p>
            <ActionCoverageDetails coverage={assessment.action.coverage} />
          </>
        )}
        {coverage.hasGaps && (
          <p className="score-explanation">{coverage.detail}</p>
        )}
        {record?.policy_trace && (
          <PolicyTraceDetails trace={record.policy_trace} />
        )}
      </details>
    </div>
  );
}
