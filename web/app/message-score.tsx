import { coveragePresentation, receiptAssessment, receiptDecision } from './assessment';
import { actionReason } from './action-coverage';
import { ActionCoverageDetails } from './action-coverage-view';
import { PolicyTraceDetails } from './policy-trace-view';
import { ScoreMeter } from './brand';
import { scorePresentation, type ScoreInput } from './presentation';

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
  verdict,
}: {
  mail: ScoreInput;
  verdict?: { label: string; tone: string };
}) {
  const score = scorePresentation(mail);
  const coverage = coveragePresentation(mail);
  const assessment = receiptAssessment(mail);
  const record = receiptDecision(mail);
  const boundary = assessment?.score_boundary?.version === 1 ? assessment.score_boundary : null;
  const fusionScore = assessment?.score.source === 'decision' && assessment.decision.source === 'fusion';
  const category = assessment?.category;
  const shown = verdict ?? (category === 'spam' ? { label: 'Spam', tone: 'spam' }
    : category === 'publicity' ? { label: 'Pub', tone: 'publicity' }
    : category === 'legitimate' ? { label: 'Ham', tone: 'good' }
    : { label: 'Not recorded', tone: 'neutral' });
  const action = assessment?.action;
  const actions: Record<string, string> = {deliver: 'Deliver', tag: 'Tag and deliver', quarantine: 'Quarantine'};
  const coverageTone = coverage.complete && !coverage.hasGaps ? 'good' : 'review';
  return (
    <div className={`message-score-details ${score.kind}`}>
      <dl className="analysis-overview" aria-label="NoiseFence receipt summary">
        <div className="analysis-stat analysis-verdict">
          <dt className="analysis-stat-label">NoiseFence verdict</dt>
          <dd className={`status ${shown.tone}`}>{shown.label}</dd>
          <dd className="analysis-stat-note">NoiseFence&apos;s independent decision</dd>
        </div>
        <div className="analysis-stat">
          <dt className="analysis-stat-label">{score.label}</dt>
          <dd className="score-large">{score.value?.toFixed(1) ?? '—'}{score.value !== null && <span>/ 100</span>}</dd>
          <dd className="analysis-stat-note">{score.value === null ? 'No usable value recorded' : 'Risk index, not a probability'}</dd>
        </div>
        <div className="analysis-stat">
          <dt className="analysis-stat-label">Analysis coverage</dt>
          <dd className={`status ${coverageTone}`}>{coverage.label}</dd>
          <dd className="analysis-stat-note">Coverage is separate from the verdict</dd>
        </div>
        <div className="analysis-stat">
          <dt className="analysis-stat-label">Action at receipt</dt>
          <dd className="analysis-action-value">{action ? actions[action.effective] ?? 'Not recorded' : 'Not recorded'}</dd>
          <dd className="analysis-stat-note">{assessment?.mode === 'observe' ? 'Observation mode' : 'Recorded policy'} · not delivery confirmation</dd>
        </div>
      </dl>
      <p className="analysis-summary-note">{action ? actionReason(action.reason) + '. ' : ''}{coverage.detail}</p>
      <details className="analysis-explanation">
        <summary>Decision basis, score boundary and policy</summary>
        <p className="score-label">
          <strong>{score.label}</strong>
          {score.model && <span> · {score.model}</span>}
        </p>
        <p className="score-explanation">{score.detail}</p>
        <div className="assessment-facts">
          <span title={coverage.detail} className={`status ${coverageTone}`}>{coverage.label}</span>
          {boundary ? <span>Recorded score boundary: <strong>{boundary.cutoff} {boundary.source === 'fusion' ? 'logit' : '/ 100'}</strong></span>
            : fusionScore ? <span>Fusion boundary not recorded</span>
            : assessment?.content_threshold != null && <span>Recorded content threshold: <strong>{assessment.content_threshold} / 100</strong></span>}
          {assessment?.classification_source === 'historical_fallback' && <span>{assessment.content_threshold == null ? 'Original policy not recorded' : 'Historical classification reconstructed'}</span>}
          {record && <span>Receipt policy: <code title={record.policy_sha256}>{record.policy_sha256.slice(0, 12)}</code></span>}
          {record?.profile && <span>Profile: <strong>{record.profile}</strong></span>}
        </div>
        {boundary && <p className="score-explanation">
          {boundary.source === 'fusion' ? <>Fusion compares its native logit ({boundary.value}) with the recorded cutoff ({boundary.cutoff}). Mapped boundary: {boundary.index_cutoff} / 100. The native comparison applies even when displayed scores round to the same value. </> : <>The content index is compared with the recorded content threshold. </>}
          Comparison: {boundary.above ? 'at or above' : 'below'} the boundary. Evidence, recipient rules and delivery restrictions can take precedence.
        </p>}
        {record && assessment?.action && <><p className="score-explanation">Requested action: {assessment.action.requested}. Effective action: {assessment.action.effective}. {actionReason(assessment.action.reason)}. This decision is preserved when settings change.</p><ActionCoverageDetails coverage={assessment.action.coverage} /></>}
        {coverage.hasGaps && <p className="score-explanation">{coverage.detail}</p>}
        {record?.policy_trace && <PolicyTraceDetails trace={record.policy_trace} />}
      </details>
    </div>
  );
}
