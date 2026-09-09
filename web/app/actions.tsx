'use client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

export type DeliveryAction = 'deliver' | 'tag' | 'quarantine';
export type ActionPolicy = {
  spam: DeliveryAction;
  publicity: DeliveryAction;
  malware: DeliveryAction;
  quarantine_days: number;
};
export type Rule = { id: string; label: string; weight: number };
export const actionLabel: Record<DeliveryAction, string> = {
  deliver: 'Transmettre sans préfixe',
  tag: 'Tagger et transmettre',
  quarantine: 'Placer en quarantaine',
};

export function ActionSettings({
  policy,
  mode,
  spamTagReady,
  pubTagReady,
  publicityEnabled,
  onChange,
}: {
  policy: ActionPolicy;
  mode: string;
  spamTagReady: boolean;
  pubTagReady: boolean;
  publicityEnabled: boolean;
  onChange: (value: ActionPolicy) => void;
}) {
  return (
    <section className="panel delivery-actions">
      <h2>Actions après détection</h2>
      <p className="muted">
        Choisissez le traitement de chaque catégorie. La détection de malware
        prime sur le spam et les publicités.
      </p>
      <div className="form-grid">
        {(
          [
            ['malware', 'Malware confirmé', spamTagReady],
            ['spam', 'Spam détecté', spamTagReady],
            ['publicity', 'Publicité / newsletter (PUB)', pubTagReady],
          ] as const
        ).map(([key, label, tagReady]) => (
          <label className="field" key={key}>
            {label}
            <select
              aria-label={`Action : ${label}`}
              value={policy[key]}
              disabled={key === 'publicity' && !publicityEnabled}
              onChange={(e) =>
                onChange({ ...policy, [key]: e.target.value as DeliveryAction })
              }
            >
              <option value="deliver">Transmettre sans préfixe</option>
              <option value="tag" disabled={!tagReady}>
                Tagger {key === 'publicity' ? '[PUB]' : '[SPAM]'} et transmettre
                {!tagReady ? ' — validation requise' : ''}
              </option>
              <option value="quarantine">Placer en quarantaine</option>
            </select>
            {key === 'publicity' && !publicityEnabled && (
              <small>
                Activez la catégorisation PUB pour appliquer cette action.
              </small>
            )}
          </label>
        ))}
        <label className="field" htmlFor="quarantine-days">
          Conservation en quarantaine (jours)
          <Input
            id="quarantine-days"
            aria-label="Durée de quarantaine en jours"
            type="number"
            min={1}
            max={30}
            step={1}
            value={policy.quarantine_days}
            onChange={(e) =>
              onChange({ ...policy, quarantine_days: Number(e.target.value) })
            }
          />
          <small>
            De 1 à 30 jours. À expiration, la livraison retenue est supprimée
            sans envoi. La date fixée à la réception reste inchangée si vous
            modifiez ce réglage.
          </small>
        </label>
      </div>
      <p className="small muted">
        Les utilisateurs peuvent libérer ou supprimer les messages retenus pour
        leurs destinataires. Une libération transmet le message sans préfixe et
        conserve son classement. Une correction « Légitime » ou « Spam » ne
        libère pas un message.
      </p>
      <p className="small muted">
        Une analyse incomplète transmet sans préfixe, sauf si l’antivirus
        principal confirme un malware et que son action est « Quarantaine ».
      </p>
      {mode === 'observe' && (
        <p className="notice">
          Observation active : les actions sont enregistrées comme intentions.
          Tous les messages sont transmis sans préfixe et aucun n’est retenu.
        </p>
      )}
    </section>
  );
}

export function RuleSettings({
  rules,
  weights,
  onChange,
}: {
  rules: Rule[];
  weights: Record<string, number>;
  onChange: (weights: Record<string, number>) => void;
}) {
  return (
    <section className="panel">
      <h2>Règles heuristiques personnalisées</h2>
      <p className="muted">
        Réglez leur contribution à l’indice de suspicion. Un poids de 0
        neutralise la contribution explicite de la règle. L’observation et les
        caractéristiques utilisées par les modèles sont conservées.
      </p>
      <p className="small muted">
        Poids de 0 à 3, ajoutés avant la conversion du score : ce ne sont pas
        des pourcentages. Ces réglages ne remplacent ni la confirmation du spam,
        ni la décision d’une fusion validée, ni la priorité antivirus.
      </p>
      <div className="form-grid">
        {rules.map((rule) => (
          <label key={rule.id} className="field">
            {rule.label}
            <Input
              aria-label={`Poids : ${rule.label}`}
              type="number"
              min={0}
              max={3}
              step={0.1}
              value={weights[rule.id] ?? rule.weight}
              onChange={(e) =>
                onChange({ ...weights, [rule.id]: Number(e.target.value) })
              }
            />
            <small>
              Valeur par défaut : {rule.weight.toLocaleString('fr-FR')}
            </small>
          </label>
        ))}
      </div>
      <Button
        variant="outline"
        disabled={!Object.keys(weights).length}
        onClick={() => onChange({})}
      >
        Rétablir les poids par défaut
      </Button>
    </section>
  );
}
