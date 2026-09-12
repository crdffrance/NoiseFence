'use client';
import { useState } from 'react';
import { SlidersHorizontal, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  emptySearch,
  searchFilterCount,
  searchParameters,
  type SearchFilters,
} from './message-search';

export function MessageSearchControls({
  value,
  onChange,
}: {
  value: SearchFilters;
  onChange: (filters: SearchFilters) => void;
}) {
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState(value);
  const [error, setError] = useState('');
  const [previousValue, setPreviousValue] = useState(value);
  if (value !== previousValue) {
    setPreviousValue(value);
    setDraft(value);
    setError('');
  }
  const count = searchFilterCount(value);
  return (
    <div className="advanced-mail-search">
      <div className="search-help-row">
        <p>
          Objets, adresses, règles et identifiants · Tous les mots sont
          recherchés. Utilisez «&nbsp;<code>&quot;expression exacte&quot;</code>
          &nbsp;» pour une expression.
        </p>
        <Button
          variant={count ? 'secondary' : 'ghost'}
          aria-expanded={open}
          aria-controls="mail-search-fields"
          onClick={() => setOpen(!open)}
        >
          <SlidersHorizontal size={15} /> Recherche avancée
          {count ? ` (${count})` : ''}
        </Button>
      </div>
      {open && (
        <form
          id="mail-search-fields"
          className="search-fields-panel"
          onSubmit={(event) => {
            event.preventDefault();
            try {
              searchParameters('', 'all', '', 0, draft);
              setError('');
              onChange({ ...draft });
            } catch (e) {
              setError((e as Error).message);
            }
          }}
        >
          <div className="search-fields-grid">
            {(
              [
                ['node', 'Serveur MX', 'mx2 ou local'],
                ['sender', 'Expéditeur', 'adresse ou domaine'],
                ['recipient', 'Destinataire', 'adresse ou alias autorisé'],
                ['subject', 'Objet', 'mots ou "expression exacte"'],
                ['rule', 'Règle déclenchée', 'identifiant de règle'],
                ['id', 'Identifiant NoiseFence', 'identifiant ou fragment'],
              ] as const
            ).map(([field, label, placeholder]) => (
              <label key={field}>
                {label}
                <Input
                  value={draft[field]}
                  maxLength={256}
                  placeholder={placeholder}
                  onChange={(e) =>
                    setDraft({ ...draft, [field]: e.target.value })
                  }
                />
              </label>
            ))}
            <label>
              Livraison
              <select
                value={draft.status}
                onChange={(e) => setDraft({ ...draft, status: e.target.value })}
              >
                <option value="">Tous les états</option>
                <option value="pending">En attente</option>
                <option value="sending">En cours</option>
                <option value="delivered">Livré</option>
                <option value="failed">Échec</option>
                <option value="notified">Échec notifié</option>
                <option value="quarantined">En quarantaine</option>
                <option value="discarded">Supprimé</option>
              </select>
            </label>
            <label htmlFor="search-after">
              Reçu à partir du
              <Input
                type="date"
                id="search-after"
                value={draft.after}
                onChange={(e) => setDraft({ ...draft, after: e.target.value })}
              />
            </label>
            <label htmlFor="search-before">
              Reçu jusqu’au (inclus)
              <Input
                type="date"
                id="search-before"
                value={draft.before}
                onChange={(e) => setDraft({ ...draft, before: e.target.value })}
              />
            </label>
            <label htmlFor="search-min_score">
              Score minimum / 100
              <Input
                type="number"
                min={0}
                max={100}
                step="any"
                placeholder="0"
                id="search-min_score"
                value={draft.min_score}
                onChange={(e) =>
                  setDraft({ ...draft, min_score: e.target.value })
                }
              />
            </label>
            <label htmlFor="search-max_score">
              Score maximum / 100
              <Input
                type="number"
                min={0}
                max={100}
                step="any"
                placeholder="100"
                id="search-max_score"
                value={draft.max_score}
                onChange={(e) =>
                  setDraft({ ...draft, max_score: e.target.value })
                }
              />
            </label>
          </div>
          <p className="search-retention">
            Recherche locale dans les métadonnées conservées 30 jours et les
            messages encore en file. Les corps et pièces jointes ne sont pas
            indexés. Les dates utilisent votre fuseau horaire et les scores
            correspondent aux valeurs affichées, y compris les scores partiels.
          </p>
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
          <div className="search-field-actions">
            <Button type="submit">Appliquer les critères</Button>
            <Button
              type="button"
              variant="ghost"
              onClick={() => {
                setDraft(emptySearch);
                onChange(emptySearch);
                setError('');
              }}
            >
              <X size={14} /> Effacer les critères
            </Button>
          </div>
        </form>
      )}
    </div>
  );
}
