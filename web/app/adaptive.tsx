'use client';
import { useEffect, useState } from 'react';
import { api } from './client';
import { adaptiveClasses, adaptiveLabels, adaptiveStatus, type AdaptiveClass, type AdaptiveReport } from './adaptive-types';

export function AdaptiveDetails({ id, csrf, report, feedbackRevision, onCorrect, blocked, onBusy }: {
  id: string; csrf: string; report?: AdaptiveReport | null; feedbackRevision: number;
  onCorrect: (value: AdaptiveClass | null) => void; blocked: boolean; onBusy: (busy:boolean)=>void;
}) {
  const [domains, setDomains] = useState<{domain:string;class:AdaptiveClass|null}[]>([]);
  const [error, setError] = useState(''); const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState(''); const [revision, setRevision] = useState(0);
  useEffect(() => {
    let current = true;
    api<{domains:typeof domains}>(`/messages/${id}/adaptive-label`).then(data => {
      if (current) { setDomains(data.domains); setError(''); }
    }).catch(() => { if (current) setError('Annotations indisponibles pour ce message.'); });
    return () => { current = false; };
  }, [id, feedbackRevision, revision]);
  async function save(domain: string, value: string) {
    setBusy(true); onBusy(true); setNotice(''); setError('');
    const category = value === '' ? null : value as AdaptiveClass;
    try {
      await api(`/messages/${id}/adaptive-label`, {domain, class:category}, csrf);
      setRevision(r=>r+1); onCorrect(category);
      setNotice(category ? 'Annotation humaine enregistrée. La livraison reste inchangée.' : 'Catégorie détaillée retirée. La correction générale reste enregistrée.');
    } catch { setError('Enregistrement impossible. Réessayez après actualisation.'); }
    finally { setBusy(false); onBusy(false); }
  }
  return <section aria-label="Apprentissage local multiclasse" className="mt-5 space-y-3 rounded-xl border p-4">
    <h3>Apprentissage local · Bayes et réseau neuronal</h3>
    <p className="muted">Observation uniquement. Les modèles apprennent de vos annotations par domaine. Aucun de ces avis ne change le score ni la livraison.</p>
    <p className="muted">Précisez uniquement les catégories que vous avez vérifiées : Phishing pour le vol d’identifiants, Escroquerie pour la fraude, PUB pour les campagnes commerciales légitimes. En cas de doute, laissez sans annotation.</p>
    {domains.map(d=><label key={d.domain} className="flex flex-wrap items-center gap-3">
      <span>Annotation · {d.domain}</span>
      <select aria-label={`Catégorie humaine pour ${d.domain}`} value={d.class ?? ''} disabled={busy || blocked} onChange={e=>void save(d.domain,e.target.value)} className="rounded-lg border bg-background p-2">
        <option value="">Sans catégorie détaillée</option>
        {adaptiveClasses.map(c=><option key={c} value={c}>{adaptiveLabels[c]}</option>)}
      </select>
    </label>)}
    <details><summary>Avis Bayes et neuronal</summary>
    <p>{report ? adaptiveStatus(report.status) : 'Pas d’observation multiclasse enregistrée pour ce message.'}{report?.model && ` · ${report.model}`}</p>
    {report?.category && <p>Avis : <strong>{adaptiveLabels[report.category]}</strong>{report.proposed_action && ` · action simulée : ${{observe:'observation',tag:'marquage',quarantine:'quarantaine'}[report.proposed_action]}`}</p>}
    {report?.bayes_strengths?.length === 5 && report.neural_strengths?.length === 5 && <div className="overflow-x-auto">
      <table className="adaptive-scores"><caption>Forces relatives non calibrées ; ce ne sont pas des probabilités de menace.</caption>
        <thead><tr><th>Catégorie</th><th>Bayes</th><th>Neuronal</th></tr></thead>
        <tbody>{adaptiveClasses.map((c,i)=><tr key={c}><th>{adaptiveLabels[c]}</th><td>{report.bayes_strengths![i].toFixed(3)}</td><td>{report.neural_strengths![i].toFixed(3)}</td></tr>)}</tbody>
      </table>
    </div>}
    </details>
    {notice && <output className="block">{notice}</output>}{error && <p role="alert">{error}</p>}
  </section>;
}
