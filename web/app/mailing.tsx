'use client';

export type FeedbackCategory = 'spam' | 'publicity' | 'legitimate';
export type MailingPolicy = {
  include_newsletters: boolean;
  tag_subject: boolean;
};
export type MailingReport = {
  version: string;
  status: 'complete' | 'limited';
  verdict:
    | 'none'
    | 'promotion'
    | 'newsletter'
    | 'transactional'
    | 'conversation';
  reasons: { id: string; detail: string }[];
  elapsed_us: number;
};

export function MailingSettings({
  policy,
  available,
  tagReady,
  mode,
  onChange,
}: {
  policy: MailingPolicy | null;
  available: boolean;
  tagReady: boolean;
  mode: 'observe' | 'tag';
  onChange: (value: MailingPolicy | null) => void;
}) {
  return (
    <section className="panel mailing-settings">
      <h2>Publicités et newsletters</h2>
      <p className="muted">
        La catégorie PUB distingue les diffusions commerciales des autres
        messages légitimes. Un classement spam reste toujours prioritaire.
      </p>
      <label
        className="toggle-row"
        aria-label="Distinguer les publicités (PUB)"
      >
        <span>
          <strong>Distinguer les publicités (PUB)</strong>
        </span>
        <input
          type="checkbox"
          role="switch"
          aria-checked={!!policy}
          checked={!!policy}
          disabled={!available}
          onChange={(e) =>
            onChange(
              e.target.checked
                ? {
                    include_newsletters: true,
                    tag_subject: mode === 'observe' || tagReady,
                  }
                : null,
            )
          }
        />
      </label>
      {!available && (
        <p className="notice">Module à installer sur le serveur.</p>
      )}
      {policy && (
        <>
          <label
            className="toggle-row"
            aria-label="Inclure les newsletters éditoriales"
          >
            <span>
              <strong>Inclure les newsletters éditoriales</strong>
              <small>
                Les lettres d’information sont également classées PUB.
              </small>
            </span>
            <input
              type="checkbox"
              role="switch"
              aria-checked={policy.include_newsletters}
              checked={policy.include_newsletters}
              onChange={(e) =>
                onChange({ ...policy, include_newsletters: e.target.checked })
              }
            />
          </label>
          <label
            className="toggle-row"
            aria-label="Ajouter [PUB] dans l’objet en mode marquage"
          >
            <span>
              <strong>Ajouter [PUB] dans l’objet en mode marquage</strong>
              <small>
                Un seul préfixe est ajouté. Le corps du message est conservé.
              </small>
            </span>
            <input
              type="checkbox"
              role="switch"
              aria-checked={policy.tag_subject}
              checked={policy.tag_subject}
              onChange={(e) =>
                onChange({ ...policy, tag_subject: e.target.checked })
              }
            />
          </label>
          <p className="muted small">
            Les factures, reçus, codes de connexion et conversations bénéficient
            de critères d’exclusion. Les corrections permettent d’évaluer et
            d’améliorer la détection.
          </p>
          {mode === 'observe' && (
            <p className="notice">
              Observation active : PUB apparaît dans la console. Aucun préfixe
              n’est ajouté aux messages livrés.
            </p>
          )}
          {!tagReady && (
            <p className="muted small">
              Le marquage [PUB] nécessite une validation de livraison Proton
              propre à ce préfixe et une configuration ARC valide.
            </p>
          )}
        </>
      )}
    </section>
  );
}

export function MailingDetails({
  report,
  category,
  tagged,
}: {
  report: MailingReport;
  category: string;
  tagged: boolean;
}) {
  const verdicts = {
    none: 'Aucun indice PUB concordant',
    promotion: 'Publicité commerciale',
    newsletter: 'Newsletter',
    transactional: 'Message transactionnel ou de service',
    conversation: 'Conversation ou liste de discussion',
  };
  return (
    <section className="panel">
      <h2>Publicités et newsletters</h2>
      <p>
        <strong>
          {report.status === 'limited'
            ? 'Catégorisation limitée'
            : verdicts[report.verdict]}
        </strong>
      </p>
      {category === 'spam' && (
        <p className="notice">
          Le classement spam est prioritaire sur les indices publicitaires.
        </p>
      )}
      {category === 'undetermined' && (
        <p className="notice">
          L’analyse de sécurité ne permet pas de retenir la catégorie PUB.
        </p>
      )}
      {category === 'publicity' && (
        <p className="notice">
          {tagged
            ? 'Préfixe [PUB] ajouté à la livraison.'
            : 'Catégorie PUB détectée. Aucun préfixe [PUB] ajouté à la livraison.'}
        </p>
      )}
      <ul className="reasons">
        {report.reasons.map((r) => (
          <li key={r.id}>{r.detail}</li>
        ))}
      </ul>
      <p className="muted small">
        Détecteur {report.version} · {(report.elapsed_us / 1000).toFixed(1)} ms
        · Indépendant du score spam.
      </p>
    </section>
  );
}
