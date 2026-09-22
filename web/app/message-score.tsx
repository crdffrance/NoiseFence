import { coveragePresentation, receiptAssessment } from './assessment';
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

export function MessageScoreDetails({ mail }: { mail: ScoreInput }) {
  const score = scorePresentation(mail);
  const coverage = coveragePresentation(mail);
  const assessment = receiptAssessment(mail);
  const record = mail.recipient_decision?.version === 1 ? mail.recipient_decision : null;
  return (
    <div className={`message-score-details ${score.kind}`}>
      <div className="score-large">
        {score.value?.toFixed(1) ?? '—'}
        {score.value !== null && <span>/ 100</span>}
      </div>
      <p className="score-label">
        <strong>{score.label}</strong>
        {score.model && <span> · {score.model}</span>}
      </p>
      <p className="score-explanation">{score.detail}</p>
      <div className="assessment-facts">
        <span title={coverage.detail} className={`status ${coverage.complete && !coverage.hasGaps ? 'good' : 'review'}`}>{coverage.label}</span>
        {assessment?.content_threshold != null && <span>Recorded policy threshold: <strong>{assessment.content_threshold.toFixed(1)} / 100</strong></span>}
        {assessment?.classification_source === 'historical_fallback' && <span>{assessment.content_threshold == null ? 'Original policy not recorded' : 'Historical classification reconstructed'}</span>}
        {record && <span>Receipt policy: <code title={record.policy_sha256}>{record.policy_sha256.slice(0, 12)}</code></span>}
        {record?.profile && <span>Profile: <strong>{record.profile}</strong></span>}
      </div>
      {record && assessment?.action && <p className="score-explanation">Requested action: {assessment.action.requested}. Effective action: {assessment.action.effective}. Reason: {assessment.action.reason.replaceAll('_', ' ')}. This decision is preserved when settings change.</p>}
      {coverage.hasGaps && <p className="score-explanation">{coverage.detail}</p>}
    </div>
  );
}
