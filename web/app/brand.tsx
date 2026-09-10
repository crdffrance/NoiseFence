import { Check, Mail, ShieldCheck } from 'lucide-react';

export function BrandMark({ className = '' }: { className?: string }) {
  return (
    <svg
      className={`nf-mark ${className}`}
      viewBox="0 0 40 40"
      fill="none"
      aria-hidden="true"
    >
      <rect width="40" height="40" rx="12" fill="currentColor" />
      <path d="M11 28V12h5l8 11V12h5v16h-5l-8-11v11h-5Z" fill="white" />
      <path d="m24 28 5-5v5h-5Z" fill="#FFD6B6" />
    </svg>
  );
}

export function LoginStory() {
  return (
    <section
      className="login-story"
      aria-label="NoiseFence, console de messagerie"
    >
      <div className="login-wordmark">
        <BrandMark /> NoiseFence<span>CONSOLE</span>
      </div>
      <div className="login-story-copy">
        <span className="story-kicker">
          <span /> VOTRE MESSAGERIE, SOUS CONTRÔLE
        </span>
        <h2>
          Moins de bruit.
          <br />
          <em>Plus de clarté.</em>
        </h2>
        <p>
          Gardez une longueur d’avance sur les messages indésirables. Comprenez
          chaque décision et faites place à l’essentiel.
        </p>
      </div>
      <div className="mail-flow" aria-hidden="true">
        <div className="flow-orbit orbit-one" />
        <div className="flow-orbit orbit-two" />
        <div className="flow-line" />
        <div className="flow-envelope envelope-one">
          <Mail size={23} />
          <span />
          <span />
        </div>
        <div className="flow-envelope envelope-two">
          <Mail size={21} />
          <span />
          <span />
        </div>
        <div className="flow-center">
          <BrandMark />
          <span>NoiseFence</span>
          <small>ANALYSER · COMPRENDRE · AGIR</small>
        </div>
        <div className="flow-result">
          <span>
            <ShieldCheck size={20} />
          </span>
          <div>
            Chaque message compte.<small>Vous gardez le contrôle.</small>
          </div>
          <Check size={16} />
        </div>
        <span className="flow-spark spark-one" />
        <span className="flow-spark spark-two" />
      </div>
      <div className="story-footer">
        <ShieldCheck size={16} />
        <span>Vos domaines. Vos filtres. Vos décisions.</span>
      </div>
    </section>
  );
}

export function ScoreMeter({
  score,
  tone = '',
}: {
  score: number | null;
  tone?: string;
}) {
  if (score === null || !Number.isFinite(score))
    return (
      <span className="score muted" aria-label="Indice indisponible">
        —
      </span>
    );
  const bounded = Math.max(0, Math.min(100, score));
  return (
    <span className={`score-meter ${tone}`}>
      <span className="score">{score.toFixed(1)}</span>
      <meter
        className="score-track"
        aria-label="Indice de suspicion"
        min={0}
        max={100}
        value={bounded}
      />
    </span>
  );
}
