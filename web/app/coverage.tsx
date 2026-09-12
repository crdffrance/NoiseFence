import type { Coverage, Misses } from './reliability-types';
import { detectorLabels, detailLabel, diagnosticLabel } from './reliability-types';
import { checkFailure } from './presentation';
export function CoverageDetails({data}:{data?:Coverage}) {
  if (!data) return <p>Ces diagnostics n’étaient pas enregistrés dans cette version.</p>;
  return <>
    <div className="reliability-table"><table><thead><tr><th>Fournisseur</th><th>Consultés / cache / omis</th><th>Requêtes et réponses</th><th>Incidents enregistrés</th></tr></thead><tbody>{Object.entries(data.providers).map(([name,p])=><tr key={name}>
      <td>{detectorLabels[name] || 'Fournisseur'}</td><td>{p.checked} / {p.cached} / {p.omitted}</td>
      <td>{p.requests} requêtes{Object.entries(p.http_status).map(([code,n])=><div key={code}>HTTP {code} : {n}</div>)}</td>
      <td>{Object.entries(p.failures).map(([reason,n])=><div key={reason}>{checkFailure(reason)} : {n}</div>)}{p.retry_after_max_seconds>0 && <div>Pause demandée : jusqu’à {p.retry_after_max_seconds} s</div>}</td>
    </tr>)}</tbody></table></div>
    <p>{data.redirects_complete} destinations finales atteintes · {data.redirects_omitted} URL omises.</p>
    <ul>{Object.entries(data.redirect_details).map(([reason,n])=><li key={reason}>{detailLabel(reason)} : {n}</li>)}</ul>
    <p className="muted small">Les pages volumineuses, scripts et adresses interdites restent des contrôles incomplets. Un incident récupéré peut figurer sur une analyse terminée. Les anciens messages ne possèdent pas tous les compteurs de requêtes.</p>
  </>;
}
export function MissedDetails({title,data}:{title:string;data:Misses}) {
  return <div><h3>{title}</h3><p>{data.messages} spams annotés non capturés : {data.classified_legitimate} classés légitimes, {data.review} à vérifier.</p><ul>{Object.entries(data.context).map(([name,n])=><li key={name}>{diagnosticLabel(name)} : {n}</li>)}</ul></div>;
}
