import type { Coverage, Misses } from './reliability-types';
import { detectorLabels, detailLabel, diagnosticLabel } from './reliability-types';
import { checkFailure } from './presentation';
import { timingRows } from './provider-timing';
export function CoverageDetails({data}:{data?:Coverage}) {
  if (!data) return <p>These diagnostics were not recorded by this version.</p>;
  return <>
    <div className="reliability-table"><table><thead><tr><th>Provider</th><th>Checked / cached / omitted</th><th>Requests and answers</th><th>Recorded incidents</th></tr></thead><tbody>{Object.entries(data.providers).map(([name,p])=><tr key={name}>
      <td>{detectorLabels[name] || "Provider"}{p.p95_ms != null && <p className="small">p95 {p.p95_ms} ms · {p.timed_messages ?? 0} timed messages</p>}</td><td>{p.checked} / {p.cached} / {p.omitted}</td>
      <td>{p.requests} requests{Object.entries(p.http_status).map(([code,n])=><div key={code}>HTTP {code} : {n}</div>)}
      {!!p.timed_messages&&<details><summary>Timing for {p.timed_messages} messages · {p.deadline_exceeded??0} overall deadlines</summary>
        {timingRows({budget_ms:0,deadline_exceeded:false,phase_ms:p.phase_ms??{},cancelled:p.cancelled_phases??{}}).map(r=><p key={r.phase}>{r.label}: {r.ms} ms total · {r.cancelled} interrupted</p>)}
        <p className="muted small">Operation totals, including concurrent requests; not a latency percentile.</p>
      </details>}</td>
      <td>{Object.entries(p.failures).map(([reason,n])=><div key={reason}>{checkFailure(reason)} : {n}</div>)}{p.retry_after_max_seconds>0 && <div>Longest recorded cooldown: {p.retry_after_max_seconds} s</div>}</td>
    </tr>)}</tbody></table></div>
    <p>{data.redirects_complete} completed destination checks · {data.redirects_omitted} URL(s) skipped.</p>
    <ul>{Object.entries(data.redirect_details).map(([reason,n])=><li key={reason}>{detailLabel(reason)} : {n}</li>)}</ul>
    <p className="muted small">Oversized pages, scripts and prohibited addresses remain incomplete checks. Recovered incidents can appear on completed analyses. Provider p95 uses recorded elapsed times, including failed attempts and cache lookups, only where timing metadata exists; phase totals are not percentiles. Older messages may lack counters or timings.</p>
  </>;
}
export function MissedDetails({title,data}:{title:string;data:Misses}) {
  return <div><h3>{title}</h3><p>{data.messages} Annotated spam not captured: {data.classified_legitimate} classified as legitimate, {data.review} to be checked.</p><ul>{Object.entries(data.context).map(([name,n])=><li key={name}>{diagnosticLabel(name)} : {n}</li>)}</ul></div>;
}
