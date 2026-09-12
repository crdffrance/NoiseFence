import {rblStatus,rblIncident,type EarlyRbl} from './rbl-types';
export function EarlyRblDetails({report}:{report:EarlyRbl}) {
  if (!report.checks.length) return null;
  return <section aria-label="Réputation IP avant réception">
    <h3>Réputation IP avant réception</h3>
    <p className="muted">{report.elapsed_ms} ms · {report.listed_providers} fournisseur(s) signalent l’IP · seuil : {report.minimum_providers}</p>
    <p>{report.effective_action === 'observe' ? 'Observation, sans effet supplémentaire sur le score.' : report.effective_action === 'defer' ? 'Refus SMTP temporaire.' : 'Refus SMTP définitif.'}{report.would_block && report.effective_action === 'observe' && ' Le seuil de refus serait atteint en mode application.'}</p>
    <ul>{report.checks.map(check=><li key={check.id}><strong>{check.id}</strong> · {rblStatus(check.status)}{check.cached && ' · cache'}{check.codes.length > 0 && ` · ${check.codes.join(', ')}`}{check.incident && <span> · {rblIncident(check.incident)}</span>}</li>)}</ul>
    <p className="muted">Contrôle de l’IP de connexion avant DATA. Les domaines et URL du message sont analysés séparément après réception.</p>
  </section>;
}
