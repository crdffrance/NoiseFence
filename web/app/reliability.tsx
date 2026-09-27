'use client';
import { useEffect,useState } from 'react';
import { CoverageDetails, MissedDetails } from './coverage';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { api } from './client';
import { rate,stateLabel,detectorLabels,protonLabels,type Metrics,type ReliabilityReport,type ProtonReport,type Health } from './reliability-types';
function Measures({title,data}:{title:string;data:Metrics}) {
  return <section className="panel"><h2>{title}</h2><p>{data.labelled} annotated messages</p><dl className="reliability-measures">
    <div><dt>Recall</dt><dd>{rate(data.recall)}</dd></div><div><dt>False positives</dt><dd>{rate(data.false_positive_rate)}</dd></div>
    <div><dt>Accuracy</dt><dd>{rate(data.precision)}</dd></div><div><dt>No decisive opinion</dt><dd>{rate(data.abstention)}</dd></div>
  </dl><p className="muted small">They describe these annotations; their selection and related campaigns limit any generalization to traffic.</p></section>;
}
function Proton({report}:{report:ProtonReport}) {
  return <div><h3>{report.prefix} · {stateLabel(report.status)}</h3><ul className="reliability-checklist">{report.cases.map(c=><li key={c.id}>
    <span>{protonLabels[c.id] || "Validation case"}</span><strong>{c.passed && c.evidence_present?"Documented":"Not validated"}</strong>
  </li>)}</ul></div>;
}
function Freshness({title,value}:{title:string;value:Health}) {
  return <div><h3>{title}</h3><p>{stateLabel(value.status)}</p>
    {value.database_revision!=null && <p className="muted small">Review announced: {value.database_revision}</p>}
    {value.minimum_age_seconds!=null && value.maximum_age_seconds!=null && <p className="muted small">Age of date announced: {Math.floor(value.minimum_age_seconds/3600)} to {Math.ceil(value.maximum_age_seconds/3600)} h. Freshclam’s revision is unknown; this status does not certify the exact loaded signature set.</p>}
  </div>;
}
export function ReliabilityConsole() {
  const [days,setDays]=useState(7),[domain,setDomain]=useState('');
  const [request,setRequest]=useState({days:7,domain:'',revision:0});
  const [report,setReport]=useState<ReliabilityReport|null>(null),[error,setError]=useState(''),[busy,setBusy]=useState(true);
  const [symbolSearch,setSymbolSearch]=useState('');
  const [coverageScope,setCoverageScope]=useState('current');
  useEffect(()=>{
    const controller=new AbortController();
    api<ReliabilityReport>(`/quality/reliability?days=${request.days}&domain=${encodeURIComponent(request.domain)}`,undefined,undefined,{signal:controller.signal,cache:'no-store'})
      .then(r=>{if(!controller.signal.aborted){setReport(r);setError('');setBusy(false);}})
      .catch(e=>{if(!controller.signal.aborted){setReport(null);setError(e instanceof Error?e.message:"Report unavailable.");setBusy(false);}});
    return ()=>controller.abort();
  },[request]);
  function refresh(){setBusy(true);setReport(null);setError('');setRequest({days,domain:domain.trim().toLowerCase(),revision:request.revision+1});}
  const symbols=Object.entries(report?.symbols ?? {}).filter(([id])=>id.toLowerCase().includes(symbolSearch.toLowerCase())).sort((a,b)=>b[1].spam_decision_on_legitimate-a[1].spam_decision_on_legitimate || b[1].hits-a[1].hits);
  return <div className="quality-console reliability-console">
    <section className="panel"><p className="eyebrow">FILTER RELIABILITY</p><h1>Measure before changing</h1><p>A review of your accessible messages, human corrections and the availability of controls.</p>
      <div className="quality-controls"><label>Period<select value={days} onChange={e=>setDays(Number(e.target.value))}><option value={1}>24 hours</option><option value={7}>7 days</option><option value={14}>14 days</option><option value={29}>29 days</option></select></label>
        <label htmlFor="reliability-domain">Domain (optional)<Input id="reliability-domain" value={domain} onChange={e=>setDomain(e.target.value)} placeholder="All my accessible domains"/></label>
        <Button disabled={busy} onClick={refresh}>Refresh report</Button></div>
      {error && <p role="alert" className="error">{error}</p>}{busy && <output>Calculating report…</output>}
      {report && <p className="muted small">Calculated on {new Date(report.checked_at*1000).toLocaleString("en-GB")} · {report.status==='limited'?"Partial history":"History"} · No adjustment modified.</p>}
    </section>
    {report && <>
      {report.alerts.length>0 && <section className="panel" aria-label="Items for consideration"><h2>Items for consideration</h2>{report.alerts.map((a,i)=><p className={a.level==='warning'?'notice':'muted'} key={`${a.code}:${i}`}>{a.detector && <strong>{detectorLabels[a.detector] || "Monitoring"} : </strong>}{a.detail}</p>)}</section>}
      <section className="panel"><h2>Traffic observed</h2><div className="reliability-grid">
        {[[report.observations.messages,'messages'],[report.observations.spam,"Spam"],[report.observations.review,"to be checked"],[report.observations.incomplete,"incomplete analyses"],[report.observations.disagreements,"conflicting opinions"],[report.observations.p95_ms==null?'—':`${report.observations.p95_ms} ms`,"analysis latency p95"]].map(([n,label])=><div className="reliability-stat" key={String(label)}><strong>{n}</strong><span>{label}</span></div>)}
      </div><p className="muted small">The recorded ranking does not prove the actual character of the message or its destination folder in Proton. Latency measures the recorded processing path, including external controls; it does not constitute a warm-cache benchmark.</p></section>
      <div className="reliability-columns"><Measures title="Quality annotations" data={report.quality_labels}/><Measures title="Targeted corrections" data={report.targeted_feedback}/></div>
      <section className="panel"><h2>Availability of checks</h2><p className="muted">On the last 24 hours of the balance sheet. A lack of control is not worth a negative result.</p>
        <div className="reliability-table"><table><thead><tr><th>Monitoring</th><th>Recorded states</th></tr></thead><tbody>{Object.entries(report.last_24h.detector_status).map(([name,states])=><tr key={name}><td>{detectorLabels[name] || "Monitoring"}</td><td>{Object.entries(states).map(([s,n])=>`${stateLabel(s)} : ${n}`).join(' · ')}</td></tr>)}</tbody></table></div>
        {!report.last_24h.messages && <p>No recent messages in this perimeter.</p>}
      </section>
      <section className="panel"><h2>Network coverage</h2>
        <label>Observation version<select value={coverageScope} onChange={e=>setCoverageScope(e.target.value)}><option value="current">Current engine · last 24 hours</option><option value="all">All versions · last 24 h</option></select></label>
        <p className="muted">{coverageScope==='current'?(report.current_build_last_24h?.messages ?? 0):report.last_24h.messages} messages in this group. The incidents of old versions do not necessarily describe the current engine.</p>
        <CoverageDetails data={(coverageScope==='current'?report.current_build_last_24h:report.last_24h)?.coverage}/>
      </section>
      {report.missed_diagnostics && <section className="panel"><h2>Understanding Missed Spams</h2><div className="reliability-columns"><MissedDetails title="Quality samples" data={report.missed_diagnostics.quality}/><MissedDetails title="Targeted corrections" data={report.missed_diagnostics.targeted}/></div><p className="muted small">Context recorded on spam annotated messages. Several situations may coexist; this assessment does not demonstrate their causal role. Targeted cases are used for diagnosis, random batches remain necessary for evaluation.</p></section>}
      {report.system && <section className="panel"><h2>Status of signature services</h2><div className="reliability-columns"><Freshness title="Antivirus" value={report.system.antivirus}/><Freshness title="Advisory signatures" value={report.system.signatures}/></div></section>}
      <section className="panel"><h2>Collection for calibration</h2><p>{report.current_build_observations} observations related to the current engine · {report.current_protocol_observations} to the current protocol · {report.unlabelled} Without a usable annotation.</p>
        <p className="muted">Each group below links the same controls, models and settings. The old corrections remain useful for the audit; they are not converted into new observations. Create the lots in &quot;Filter Quality&quot; and check the originals in your email.</p>
        <div className="reliability-table"><table><thead><tr><th>Collection group</th><th>Messages</th><th>Complete</th><th>Quality annotations</th><th>Period</th></tr></thead><tbody>{Object.entries(report.cohorts).sort((a,b)=>b[1].last_seen-a[1].last_seen).map(([id,c])=><tr key={id}><td><code title={id}>{id.slice(0,12)}</code>{c.current_build?" · current engine":''}</td><td>{c.messages}</td><td>{c.complete}</td><td>{c.risk_labels}</td><td>{new Date(c.first_seen*1000).toLocaleDateString("en-GB")} – {new Date(c.last_seen*1000).toLocaleDateString("en-GB")}</td></tr>)}</tbody></table></div>
        <p className="notice">The activation still requires an independent test, separated by dates and campaigns, with the objectives and their confidence intervals. No automatic activation.</p>
      </section>
      <section className="panel"><h2>Rule contributions</h2><p>Lines are sorted by errors on legitimate annotated messages, then by frequency. Several rules can describe the same event.</p>
        <label htmlFor="reliability-symbol">Find a Symbol<Input id="reliability-symbol" value={symbolSearch} onChange={e=>setSymbolSearch(e.target.value)} placeholder="Ex. model_contribution, NF_CREDENTIALS"/></label>
        <div className="reliability-table"><table><thead><tr><th>Symbol</th><th>Occurrences</th><th>Spam/Legitimate annotations</th><th>Simulated withdrawal: changed decisions</th><th>False positive avoided / lost spam</th></tr></thead><tbody>{symbols.slice(0,50).map(([id,s])=><tr key={id}><td><code>{id}</code>{s.source==='native_observation' && <small>Observation native · {s.absorbed} regroupements</small>}</td><td>{s.hits}</td><td>{s.labelled_spam} / {s.labelled_legitimate}</td><td>{s.source==='native_observation'?"Advisory":`${s.frozen_decision_changes} / ${s.replayed} reviews`}</td><td>{s.source==='native_observation'?"Not simulated":`${s.false_positives_avoided} / ${s.detected_spam_lost}`}</td></tr>)}</tbody></table></div>
        <p className="muted small">{Math.min(50,symbols.length)} / {symbols.length} Removal simulates the rule’s numerical weight with the recorded evidence and opinions. It does not simulate a new analysis path or recipient-specific actions.</p>
        <details><summary>Signals present together</summary><ul>{report.cooccurrences.slice(0,15).map(p=><li key={`${p.a}:${p.b}`}><code>{p.a}</code> + <code>{p.b}</code> : {p.hits}</li>)}</ul><p className="muted small">A co-occurrence does not demonstrate independence or causality.</p></details>
      </section>
      <section className="panel"><h2>Recorded candidate comparisons</h2>{!report.candidate_comparisons.length?<p>No paired, labelled predictions available.</p>:report.candidate_comparisons.map(c=><details key={c.cohort_model}><summary><code>{c.cohort_model.slice(0,12)}</code> · {c.baseline.labelled} messages</summary><div className="reliability-columns"><Measures title="Decision implemented" data={c.baseline}/><Measures title="Candidate for observation" data={c.candidate}/></div></details>)}<p className="muted small">This comparison covers annotated cases and is supported by the candidate and does not replace an independent assessment of his coverage and errors.</p></section>
      {report.system && <section className="panel"><h2>Validation of Proton Marking</h2><p>Policy: {report.system.proton.mode==='observe'?'observation':report.system.proton.mode}. {report.system.proton.note}</p><div className="reliability-columns"><Proton report={report.system.proton.spam}/><Proton report={report.system.proton.publicity}/></div><p className="muted small">For each case: compare direct arrival, non-modified relays and relays with prefixes; keep the received headers and the recorded folder. Reports remain subject to configuration control.</p></section>}
      <section className="panel"><details><summary>Period and balance sheet limits</summary><ul>{report.limitations.map(text=><li key={text}>{text}</li>)}</ul></details></section>
    </>}
  </div>;
}
