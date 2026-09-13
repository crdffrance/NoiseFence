import {rblStatus,rblIncident,type EarlyRbl} from './rbl-types';
export function EarlyRblDetails({report}:{report:EarlyRbl}) {
  if (!report.checks.length) return null;
  return <section aria-label="IP reputation before receipt">
    <h3>IP reputation before receipt</h3>
    <p className="muted">{report.elapsed_ms} ms · {report.listed_providers} provider(s) report IP · threshold: {report.minimum_providers}</p>
    <p>{report.effective_action === 'observe' ? "Observation, with no additional effect on the score." : report.effective_action === 'defer' ? "Temporary SMTP refusal." : "Definitive SMTP refusal."}{report.would_block && report.effective_action === 'observe' && " The refusal threshold would be reached in application mode."}</p>
    <ul>{report.checks.map(check=><li key={check.id}><strong>{check.id}</strong> · {rblStatus(check.status)}{check.cached && ' · cache'}{check.codes.length > 0 && ` · ${check.codes.join(', ')}`}{check.incident && <span> · {rblIncident(check.incident)}</span>}</li>)}</ul>
    <p className="muted">Control of connection IP before DATA. The message domains and URL are analyzed separately after receiving.</p>
  </section>;
}
