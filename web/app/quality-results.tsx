'use client';
export type Metrics={messages:number;tp:number;fp:number;review:number;spam_total?:number;legitimate_total?:number;spam_to_review?:number;legitimate_to_review?:number;recall:number|null;fpr:number|null;precision:number|null;fpr_ci95:[number,number]|null;recall_ci95:[number,number]|null};
export type MetricReport={baseline?:Metrics;rspamd?:Metrics;candidate?:Metrics};
export type RecordedPolicy={classification:Metrics;records:number;snapshots:number;legacy_without_snapshot:number;invalid_snapshots:number;
  requested_actions:Record<string,Record<string,number>>;effective_actions:Record<string,Record<string,number>>;
  action_transitions:{requested:string;effective:string;records:number}[]};
const percent=(value:number|null|undefined)=>value==null?'Not measured':`${(value*100).toFixed(2)}%`;
export function MetricTable({report,caption='Human-labelled records · missing decisions count as review', label='Engine', nativeLabel='NoiseFence'}:{report:MetricReport;caption?:string;label?:string;nativeLabel?:string}) {
  const rows=[[nativeLabel,report.baseline],['Rspamd',report.rspamd],['Candidate',report.candidate]] as const;
  return <div className="quality-table-scroll"><table className="quality-metrics"><caption>{caption}</caption><thead><tr><th>{label}</th><th>Labelled</th><th>Recall</th><th>False positives</th><th>Precision</th><th>Review</th></tr></thead><tbody>
    {rows.filter(([,m])=>m).map(([name,m])=><tr key={name}><th>{name}</th><td>{m!.messages}</td><td>{percent(m!.recall)}{m!.spam_total!=null&&<small>{m!.tp} / {m!.spam_total} confirmed spams</small>}{m!.recall_ci95&&<small>95% CI {m!.recall_ci95.map(percent).join('–')}</small>}</td><td>{m!.fp} · {percent(m!.fpr)}{m!.legitimate_total!=null&&<small>Among {m!.legitimate_total} legitimate messages</small>}{m!.fpr_ci95&&<small>95% CI {m!.fpr_ci95.map(percent).join('–')}</small>}</td><td>{percent(m!.precision)}</td><td>{m!.review}{m!.spam_to_review!=null&&<small>{m!.spam_to_review} spam · {m!.legitimate_to_review} legitimate</small>}</td></tr>)}
  </tbody></table></div>;
}

export function FullSampleResults({report}:{report:MetricReport&{evaluation_scope?:string}}) {
  const engineOnly=['recorded_engines_with_separate_policy_results','shadow_engine_with_antivirus_guard_not_recipient_policy_replay'].includes(report.evaluation_scope??'');
  return <details><summary>{engineOnly?'Full-sample engine results and coverage':'Historical mixed policy baseline'}</summary>
    <MetricTable report={report}/><p className="muted small">{engineOnly
      ?'Missing engine decisions count as review. Incomplete coverage does not erase an explicit verdict. Recipient overrides are reported separately. This population table is not the paired comparison.'
      :'This older report mixes engine decisions, recipient overrides and incomplete-analysis fallback. Its baseline cannot establish engine-only accuracy. Run a new comparison to separate these results.'}</p></details>;
}

export function PolicyResults({value}:{value?:RecordedPolicy}) {
  if (!value) return <p className="muted small">Separate recipient-policy and action results were not recorded in this report.</p>;
  const stages=[['Requested',value.requested_actions],['Effective',value.effective_actions]] as const;
  const actions=['deliver','tag','quarantine','not_recorded'];
  return <details><summary>Recipient decisions and action intentions</summary>
    <MetricTable report={{baseline:value.classification}} label="Decision" nativeLabel="Recipient policy" caption="Recorded recipient classifications · human risk labels · missing decisions count as review"/>
    <p>{value.records} labelled records · {value.snapshots} valid snapshots · {value.legacy_without_snapshot} legacy records · {value.invalid_snapshots} invalid snapshots.</p>
    <div className="quality-table-scroll"><table className="quality-metrics"><caption>Actions by human label · receipt-time intentions, not delivery confirmations</caption>
      <thead><tr><th>Stage</th><th>Human label</th><th>Deliver</th><th>Tag</th><th>Quarantine</th><th>Not recorded</th></tr></thead>
      <tbody>{stages.flatMap(([stage,counts])=>['legitimate','spam'].map(risk=><tr key={`${stage}-${risk}`}><th>{stage}</th><td>{risk==='spam'?'Unwanted':'Wanted'}</td>{actions.map(action=><td key={action}>{counts[risk]?.[action]??0}</td>)}</tr>))}</tbody></table></div>
    <p className="muted small">Observation or safety constraints can suppress requested actions. A recorded deliver action does not prove downstream delivery. Publicity is a mail type; these metrics compare wanted versus unwanted risk. Recipient-policy variants and repeated campaigns are not independent arrivals.</p>
  </details>;
}

export function TrainingResults({risk}:{risk?:{test?:Metrics}}) {
  if (!risk?.test) return <p className="muted small">No candidate test-fold metrics were recorded.</p>;
  return <><MetricTable report={{candidate:risk.test}} caption="Development sample · candidate test fold"/>
    <p className="muted small">These metrics use the development sample partition. They are not a prospective independent evaluation or recipient-policy replay.</p></>;
}

export type ExportExposure={schema:string;tracked:boolean;candidate_bound:boolean;observation_window_covered:boolean;not_previously_exposed:boolean;eligible_for_independence_checks:boolean};
function exposureEligible(value?:ExportExposure) {
  return value?.schema==='noisefence-quality-exposure-1'&&value.tracked===true&&value.candidate_bound===true&&value.observation_window_covered===true&&value.not_previously_exposed===true&&value.eligible_for_independence_checks===true;
}
export function ExposureNotice({value}:{value?:ExportExposure}) {
  if (!value||value.schema!=='noisefence-quality-exposure-1'||!value.tracked) return <p className="notice">Export-use history is not recorded for this report. It cannot establish a fresh independent test.</p>;
  return <p className="muted small">{!value.observation_window_covered
    ?'Some observations predate export tracking. Freshness is unverified.'
    :!value.not_previously_exposed
      ?'This sample or a related campaign was already exposed. Use these results for regression, not a fresh independent test.'
      :!value.candidate_bound?'This export is not bound to the evaluated candidate. It cannot establish independent qualification.':'At export time, no prior use was recorded within the tracking window. Independent labels, campaign separation and frozen candidate provenance still require validation.'}</p>;
}
export function QualificationStatus({acceptance,exposure}:{acceptance:{passes_pilot:boolean;meets_final_confidence_bounds:boolean};exposure?:ExportExposure}) {
  if (!exposureEligible(exposure)) return <p>Qualification unavailable: export freshness is not established. Recorded metrics remain visible.</p>;
  return <p>Shadow pilot: {acceptance.passes_pilot?'criteria met':'not qualified'} · Final confidence bounds: {acceptance.meets_final_confidence_bounds?'met':'not demonstrated'}.</p>;
}
