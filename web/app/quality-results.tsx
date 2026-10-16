'use client';
export type Metrics={messages:number;tp:number;fp:number;review:number;spam_total?:number;legitimate_total?:number;spam_to_review?:number;legitimate_to_review?:number;recall:number|null;fpr:number|null;precision:number|null;fpr_ci95:[number,number]|null;recall_ci95:[number,number]|null};
export type MetricReport={baseline?:Metrics;rspamd?:Metrics;candidate?:Metrics};
export type PairedDiagnostics = {
  decisive?: MetricReport & {messages:number;excluded_nonfinal:number};
  rspamd_nonfinal_actions?: Record<string,number>;
  error_overlap?: Record<string,{messages:number;both_correct:number;both_wrong:number;noisefence_only:number;rspamd_only:number}>;
};
export function PairedErrorDetails({value}:{value:PairedDiagnostics}) {
  if (!value.decisive || !value.error_overlap) return <p className="muted small">Run a new comparison to separate final verdicts from temporary Rspamd actions.</p>;
  return <details><summary>Where the engines disagree with human labels</summary>
    <p>{value.decisive.messages} messages have a final verdict from both engines. {value.decisive.excluded_nonfinal} paired analyses have a non-final opinion and are excluded from this subset.</p>
    <MetricTable report={value.decisive} caption="Same messages with two final verdicts · selection differs from full paired coverage"/>
    <div className="quality-table-scroll"><table className="quality-metrics"><caption>Errors against human labels · final-verdict subset</caption>
      <thead><tr><th>Human label</th><th>Messages</th><th>Both correct</th><th>Only NoiseFence wrong</th><th>Only Rspamd wrong</th><th>Both wrong</th></tr></thead>
      <tbody>{Object.entries(value.error_overlap).map(([risk,row])=><tr key={risk}><th>{risk==='spam'?'Unwanted':'Wanted'}</th><td>{row.messages}</td><td>{row.both_correct}</td><td>{row.noisefence_only}</td><td>{row.rspamd_only}</td><td>{row.both_wrong}</td></tr>)}</tbody>
    </table></div>
    {!!Object.keys(value.rspamd_nonfinal_actions ?? {}).length && <p>Temporary or non-final Rspamd actions: {Object.entries(value.rspamd_nonfinal_actions!).map(([action,n])=>`${action}: ${n}`).join(' · ')}.</p>}
    <p className="muted small">Greylisting and soft rejection are neither ham nor spam verdicts. This selected subset cannot replace full coverage or an independent test. Rspamd results never change NoiseFence decisions.</p>
  </details>;
}
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


export type FoldReadiness = Record<string, {
  campaigns?: number; ready: boolean; labels?: Record<string, number>;
  minimum_campaigns?: number; missing_classes?: string[];
}>;
export function TrainingReadiness({value,caption}:{value:FoldReadiness;caption:string}) {
  return <div className="quality-table-scroll"><table className="quality-metrics">
    <caption>{caption} · independent campaigns per chronological partition</caption>
    <thead><tr><th>Partition</th><th>Campaigns</th><th>Minimum</th><th>Human labels</th><th>Missing classes</th><th>Readiness</th></tr></thead>
    <tbody>{Object.entries(value).map(([name,fold])=><tr key={name}>
      <th>{name}</th><td>{fold.campaigns ?? 'Not recorded'}</td><td>{fold.minimum_campaigns ?? 'Not recorded'}</td>
      <td>{fold.labels ? Object.entries(fold.labels).map(([label,n])=>`${label}: ${n}`).join(', ') || 'None' : 'Not recorded'}</td>
      <td>{fold.missing_classes?.join(', ') || (fold.missing_classes ? 'None' : 'Not recorded')}</td>
      <td>{fold.ready ? 'Ready for development' : 'More labelled campaigns needed'}</td>
    </tr>)}</tbody></table><p className="muted small">Development readiness does not establish independent qualification. Repeated messages from one campaign do not count as independent examples.</p></div>;
}
export function TrainingFailure({code}:{code:string}) {
  const explanations:Record<string,string>={
    protected_campaign_provenance:'Protected references have incomplete campaign identities. No model was fitted. Restore verified provenance; do not remove references to make training pass. You can continue labelling the sample.',
    mixed_detector_cohorts:'This sample mixes detector versions. Create a development sample restricted to one compatible detector cohort.',
    evaluation_sample_cannot_train:'Regression and independent evaluation samples cannot be used for training. Select a development sample.',
  };
  return <p role="alert" className="notice">{explanations[code] ?? 'Research job failed. Check the worker and dataset compatibility.'} No model was activated. <code>{code}</code></p>;
}

export type ScoreTradeoffsReport={schema:string;scope:string;may_activate:boolean;excluded:Record<string,number>;
  profiles:{cohort:string;llm_state:string;messages:number;wanted:number;unwanted:number;saturated:number;
    empirical_target_possible:boolean|null;points:{threshold:number;metrics:Metrics}[]}[]};
export function ScoreTradeoffs({value}:{value:ScoreTradeoffsReport}) {
  if(value.schema!=='noisefence-score-tradeoffs-1'||value.scope!=='historical_index_only_not_policy_replay'||value.may_activate!==false)
    return <p className="notice">Score diagnostics use an unsupported report format. Run a new comparison.</p>;
  return <details><summary>Score separation and sensitivity tradeoffs</summary>
    <p className="notice">Diagnostic projections only. These tables compare the historical index with a threshold. They do not replay antivirus priority, evidence guards, recipient rules or delivery actions. No setting is changed.</p>
    <p className="muted small">Each model cohort and recorded LLM feature state is evaluated separately. Historical skipped states can combine several reasons. This is not an experiment switching the LLM off. Repeated campaigns are correlated; sample results do not qualify a production threshold.</p>
    {!value.profiles.length&&<p>No compatible human-labelled scores are available.</p>}
    {value.profiles.map(p=><details key={`${p.cohort}-${p.llm_state}`}><summary>LLM: {p.llm_state.replaceAll('_',' ')} · {p.messages} labelled messages · cohort {p.cohort.slice(0,8)}</summary>
      <p>{p.wanted} wanted · {p.unwanted} unwanted · {p.saturated} indices at or above 99.9 / 100.</p>
      <p className="notice">{p.empirical_target_possible==null
        ?'Both wanted and unwanted examples are required to assess score separation.'
        :p.empirical_target_possible
          ?'At least one tested threshold reaches the empirical targets on this sample. Independent qualification and policy replay are still required.'
          :'No tested threshold reaches both 95% capture and at most 0.1% false positives on this sample. Raising sensitivity alone does not solve the observed overlap.'}</p>
      <div className="quality-table-scroll"><table className="quality-metrics"><caption>Threshold-only projection · index / 100 · not spam probability</caption>
        <thead><tr><th>Threshold</th><th>Capture</th><th>False positives</th><th>False-positive 95% interval</th></tr></thead>
        <tbody>{p.points.map(point=><tr key={point.threshold}><th>{point.threshold}</th><td>{percent(point.metrics.recall)}</td><td>{point.metrics.fp} · {percent(point.metrics.fpr)}</td><td>{point.metrics.fpr_ci95?.map(percent).join('–')??'Not measured'}</td></tr>)}</tbody>
      </table></div></details>)}
    {Object.keys(value.excluded).length>0&&<p className="muted small">Excluded: {Object.entries(value.excluded).map(([reason,n])=>`${reason.replaceAll('_',' ')}: ${n}`).join(' · ')}.</p>}
  </details>;
}
