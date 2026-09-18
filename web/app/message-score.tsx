import { coveragePresentation } from './assessment';
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
        {mail.assessment?.content_threshold != null && <span>Recorded content threshold: <strong>{mail.assessment.content_threshold.toFixed(1)} / 100</strong></span>}
        {mail.assessment?.classification_source === 'historical_fallback' && <span>Historical classification reconstructed</span>}
      </div>
      {coverage.hasGaps && <p className="score-explanation">{coverage.detail}</p>}
    </div>
  );
}
