import {timingRows, type ProviderTiming} from './provider-timing';
export function ProviderTimingDetails({timing}:{timing?:ProviderTiming|null}) {
  if (!timing) return <p className="muted small">Phase timing was not recorded for this message.</p>;
  return <details><summary>Provider timing · {timing.budget_ms} ms budget{timing.deadline_exceeded?' · overall deadline reached':''}</summary>
    <ul>{timingRows(timing).map(r=><li key={r.phase}>{r.label}: {r.ms} ms{r.cancelled?` · ${r.cancelled} interrupted operation(s)`:''}</li>)}</ul>
    <p className="muted small">Durations sum concurrent operations and may exceed elapsed time. Response-header time includes connecting and TLS; it does not isolate provider processing. Missing reputation remains unknown.</p>
  </details>;
}
