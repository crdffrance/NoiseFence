'use client';
import { useState } from 'react';
import { Input } from '@/components/ui/input';
import type { CustomPolicy } from './custom-filtering';
import type { ActionPolicy } from './actions';
import {
  levelValue,
  scopedProfile,
  setScopeThreshold,
  type SensitivityLevel,
} from './filter-sensitivity';

export function SensitivitySelect({
  threshold,
  levels,
  locked,
  onChange,
  label,
  inheritedLabel = 'Hériter du niveau général',
}: {
  threshold: number | null;
  levels: SensitivityLevel[];
  locked: boolean;
  onChange: (value: number | null) => void;
  label: string;
  inheritedLabel?: string;
}) {
  // Preserve an explicit custom editing mode even when its value matches a preset.
  const [custom, setCustom] = useState(false);
  return (
    <div className="sensitivity-select">
      <label>
        {label}
        <select
          disabled={locked}
          value={
            custom && threshold !== null
              ? 'custom'
              : levelValue(threshold, levels)
          }
          onChange={(e) => {
            setCustom(e.target.value === 'custom');
            onChange(
              e.target.value === 'inherit'
                ? null
                : e.target.value === 'custom'
                  ? (threshold ?? 95)
                  : levels.find((l) => l.id === e.target.value)!.threshold,
            );
          }}
        >
          <option value="inherit">{inheritedLabel}</option>
          {levels.map((l, i) => (
            <option key={l.id} value={l.id}>
              {i + 1} · {l.label} · seuil {l.threshold}
            </option>
          ))}
          <option value="custom">Personnalisé</option>
        </select>
      </label>
      {(custom || levelValue(threshold, levels) === 'custom') &&
        threshold !== null && (
          <label>
            Seuil personnalisé pour {label.toLowerCase()}
            <Input
              type="number"
              min={50}
              max={100}
              step={0.1}
              disabled={locked}
              value={threshold}
              onChange={(e) => onChange(Number(e.target.value))}
            />
          </label>
        )}
    </div>
  );
}

export function FilterSensitivity({
  policy,
  onChange,
  domains,
  actions,
  levels,
  locked,
  modelThreshold,
}: {
  policy: CustomPolicy | null | undefined;
  onChange: (p: CustomPolicy | null) => void;
  domains: string[];
  actions: ActionPolicy;
  levels: SensitivityLevel[];
  locked: boolean;
  modelThreshold: number;
}) {
  const [error, setError] = useState('');
  const threshold = scopedProfile(policy, '*')?.threshold ?? null;
  function update(scope: string, value: number | null) {
    try {
      onChange(setScopeThreshold(policy, scope, value, actions));
      setError('');
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Réglage invalide.');
    }
  }
  return (
    <section
      className="panel sensitivity-panel"
      aria-labelledby="sensitivity-title"
    >
      <div className="section-heading">
        <div>
          <p className="eyebrow">Sensibilité du classement</p>
          <h2 id="sensitivity-title">Du plus tolérant au plus strict</h2>
        </div>
        <span className="status">5 niveaux</span>
      </div>
      <p className="muted">
        Un niveau plus strict abaisse le seuil et augmente le nombre de messages
        suspects. Les indices ne sont pas des probabilités ; validez le réglage
        avec vos corrections.
      </p>
      {locked && (
        <p className="notice">
          La fusion validée impose son propre seuil. Ces réglages nécessitent
          une nouvelle validation de la fusion.
        </p>
      )}
      <fieldset
        className="sensitivity-levels"
        aria-label="Niveau de l’organisation"
      >
        {levels.map((l, i) => (
          <button
            type="button"
            key={l.id}
            disabled={locked}
            aria-pressed={threshold === l.threshold}
            className="sensitivity-level"
            onClick={() => update('*', l.threshold)}
          >
            <span className="sensitivity-step">{i + 1}</span>
            <strong>{l.label}</strong>
            <span className="small">Seuil {l.threshold} / 100</span>
          </button>
        ))}
      </fieldset>
      <output className="sensitivity-explanation">
        <strong>
          {threshold === null
            ? 'Hériter du moteur'
            : (levels.find((l) => l.threshold === threshold)?.label ??
              'Personnalisé')}{' '}
          · seuil {threshold ?? modelThreshold}
        </strong>
        <span>
          {threshold === null
            ? 'Le niveau suit le seuil de référence du moteur.'
            : (levels.find((l) => l.threshold === threshold)?.description ??
              'Le seuil personnalisé conserve les mêmes contrôles de confirmation.')}
        </span>
      </output>
      <SensitivitySelect
        label="Niveau général"
        levels={levels}
        threshold={threshold}
        locked={locked}
        inheritedLabel={`Hériter du moteur · seuil ${modelThreshold}`}
        onChange={(v) => update('*', v)}
      />
      <p className="small muted">
        Chaque niveau exige une confirmation du spam et conserve l’arbitrage des
        avis contradictoires, les limites d’analyse et la priorité antivirus. Le
        modèle et la sélection des analyses externes restent identiques.
      </p>
      {domains.length > 0 && (
        <div className="sensitivity-domains">
          <h3>Exceptions par domaine</h3>
          <p className="small muted">
            Les adresses ayant un profil spécifique restent prioritaires. Les
            actions Spam, Publicité et À examiner se règlent dans Règles &amp;
            profils ; créer un niveau reprend les actions actuelles.
          </p>
          {domains.map((domain) => (
            <div className="sensitivity-domain" key={domain}>
              <strong>{domain}</strong>
              <SensitivitySelect
                label={`Niveau pour ${domain}`}
                levels={levels}
                threshold={
                  scopedProfile(policy, `*@${domain}`)?.threshold ?? null
                }
                locked={locked}
                inheritedLabel={`Hériter du général · seuil ${threshold ?? modelThreshold}`}
                onChange={(v) => update(`*@${domain}`, v)}
              />
            </div>
          ))}
        </div>
      )}
      <p className="small">
        Utilisez « Vérifier et appliquer » pour enregistrer ces choix pour les
        prochains messages. Le mode observation continue de transmettre.
      </p>
      {error && (
        <p role="alert" className="notice">
          {error}
        </p>
      )}
    </section>
  );
}
