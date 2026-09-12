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
        label={`${score.label} sur 100`}
      />
      <span className="score-caption">{score.label}</span>
    </span>
  );
}

export function MessageScoreDetails({ mail }: { mail: ScoreInput }) {
  const score = scorePresentation(mail);
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
    </div>
  );
}
