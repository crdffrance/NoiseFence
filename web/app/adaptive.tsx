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
    }).catch(() => { if (current) setError("Annotations not available for this message."); });
    return () => { current = false; };
  }, [id, feedbackRevision, revision]);
  async function save(domain: string, value: string) {
    setBusy(true); onBusy(true); setNotice(''); setError('');
    const category = value === '' ? null : value as AdaptiveClass;
    try {
      await api(`/messages/${id}/adaptive-label`, {domain, class:category}, csrf);
      setRevision(r=>r+1); onCorrect(category);
      setNotice(category ? "Human annotation recorded. Delivery remains unchanged." : "Detailed category withdrawn. The general correction remains recorded.");
    } catch { setError("Record impossible. Try again after updating."); }
    finally { setBusy(false); onBusy(false); }
  }
  return <section aria-label="Local multiclass learning" className="mt-5 space-y-3 rounded-xl border p-4">
    <h3>Local learning · Bayes and neural network</h3>
    <p className="muted">Observation only. Models learn from your annotations by domain. None of these reviews changes the score or delivery.</p>
    <p className="muted">Annotate only categories you have verified: phishing for credential theft, scam for fraud, and marketing for legitimate campaigns. Leave uncertain cases unlabelled.</p>
    {domains.map(d=><label key={d.domain} className="flex flex-wrap items-center gap-3">
      <span>Annotation · {d.domain}</span>
      <select aria-label={`Human label for ${d.domain}`} value={d.class ?? ''} disabled={busy || blocked} onChange={e=>void save(d.domain,e.target.value)} className="rounded-lg border bg-background p-2">
        <option value="">No detailed category</option>
        {adaptiveClasses.map(c=><option key={c} value={c}>{adaptiveLabels[c]}</option>)}
      </select>
    </label>)}
    <details><summary>Bayes and neural opinions</summary>
    <p>{report ? adaptiveStatus(report.status) : "No multiclass observation recorded for this message."}{report?.model && ` · ${report.model}`}</p>
    {report?.category && <p>Opinion: <strong>{adaptiveLabels[report.category]}</strong>{report.proposed_action && ` · simulated action: ${{observe:'observation',tag:'tagging',quarantine:"quarantine"}[report.proposed_action]}`}</p>}
    {report?.bayes_strengths?.length === 5 && report.neural_strengths?.length === 5 && <div className="overflow-x-auto">
      <table className="adaptive-scores"><caption>Uncalibrated relative forces; these are not threat probabilities.</caption>
        <thead><tr><th>Category</th><th>Bayes</th><th>Neural</th></tr></thead>
        <tbody>{adaptiveClasses.map((c,i)=><tr key={c}><th>{adaptiveLabels[c]}</th><td>{report.bayes_strengths![i].toFixed(3)}</td><td>{report.neural_strengths![i].toFixed(3)}</td></tr>)}</tbody>
      </table>
    </div>}
    </details>
    {notice && <output className="block">{notice}</output>}{error && <p role="alert">{error}</p>}
  </section>;
}
