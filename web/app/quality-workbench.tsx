'use client';
import {useEffect,useState} from 'react';
import {Button} from '@/components/ui/button';
import {api,type User} from './client';
export type DatasetPurpose='development'|'regression'|'holdout';
type Metrics={messages:number;tp:number;fp:number;review:number;spam_total?:number;legitimate_total?:number;spam_to_review?:number;legitimate_to_review?:number;recall:number|null;fpr:number|null;precision:number|null;fpr_ci95:[number,number]|null;recall_ci95:[number,number]|null};
type Readiness=Record<string,{campaigns?:number;ready:boolean;classes?:Record<string,number>}>;
type Report={status?:string;error_code?:string;coverage?:Record<string,number>;baseline?:Metrics;rspamd?:Metrics;candidate?:Metrics;
  paired?:{baseline:Metrics;rspamd:Metrics;coverage:Record<string,number>;campaigns:Report['campaigns'];capture_comparison_supported:boolean;profiles:{native:string;rspamd:string;messages:number}[]};
  campaigns?:{count?:number;conflicting?:number;baseline?:Metrics;rspamd?:Metrics;candidate?:Metrics};
  mail_kind?:{publicity?:Metrics};legacy_score_calibration?:{reliability:{bin:number;count:number;mean_prediction:number;spam_fraction:number}[]};
  readiness?:{risk:Readiness;kind:Readiness};cohorts?:Record<string,{messages:number;readiness:Readiness}>;
  acceptance?:{passes_pilot:boolean;meets_final_confidence_bounds:boolean};native_parity?:string;
  pipeline_latency?:{samples:number;p95_ms:number|null;scope:string};limitations?:string[]};
type Job={id:string;batch:string;operation:string;status:string;created:number;report:Report|null;model_sha256:string|null};
type State={jobs:Job[];revision:number;selection:{job:string|null}|null;worker:{heartbeat:number;build:string}|null};
const percent=(value:number|null|undefined)=>value==null?'Not measured':`${(value*100).toFixed(2)}%`;
function MetricTable({report,caption='Human-labelled messages · missing decisions count as review'}:{report:Report;caption?:string}) {
  const rows=[['NoiseFence',report.baseline],['Rspamd',report.rspamd],['Candidate',report.candidate]] as const;
  return <div className="quality-table-scroll"><table className="quality-metrics"><caption>{caption}</caption><thead><tr><th>Engine</th><th>Labelled</th><th>Recall</th><th>False positives</th><th>Precision</th><th>Review</th></tr></thead><tbody>
    {rows.filter(([,m])=>m).map(([name,m])=><tr key={name}><th>{name}</th><td>{m!.messages}</td><td>{percent(m!.recall)}{m!.spam_total!=null&&<small>{m!.tp} / {m!.spam_total} confirmed spams</small>}{m!.recall_ci95&&<small>95% CI {m!.recall_ci95.map(percent).join('–')}</small>}</td><td>{m!.fp} · {percent(m!.fpr)}{m!.legitimate_total!=null&&<small>Among {m!.legitimate_total} legitimate messages</small>}{m!.fpr_ci95&&<small>95% CI {m!.fpr_ci95.map(percent).join('–')}</small>}</td><td>{percent(m!.precision)}</td><td>{m!.review}{m!.spam_to_review!=null&&<small>{m!.spam_to_review} spam · {m!.legitimate_to_review} legitimate</small>}</td></tr>)}
  </tbody></table></div>;
}
function Folds({value}:{value:Readiness}) {
  return <div className="quality-folds">{Object.entries(value).map(([name,fold])=><div key={name} className={fold.ready?'ready':'pending'}><strong>{name}</strong><span>{fold.ready?'Ready':'More labelled campaigns needed'}</span></div>)}</div>;
}
export function QualityWorkbench({user,batch,purpose,refresh}:{user:User;batch:string;purpose:DatasetPurpose;refresh:number}) {
  const [state,setState]=useState<State|null>(null),[tick,setTick]=useState(0),[candidate,setCandidate]=useState('');
  const [loadedAt,setLoadedAt]=useState(0);
  const [busy,setBusy]=useState(false),[error,setError]=useState('');
  useEffect(()=>{const c=new AbortController();api<State>('/quality/jobs',undefined,undefined,{signal:c.signal}).then(value=>{if(!c.signal.aborted){setState(value);setLoadedAt(Date.now()/1000);}}).catch(e=>{if(!c.signal.aborted)setError(e.message);});return()=>c.abort();},[tick,refresh]);
  useEffect(()=>{if(!state?.jobs.some(j=>['queued','running'].includes(j.status)))return;const t=setTimeout(()=>setTick(n=>n+1),5000);return()=>clearTimeout(t);},[state]);
  async function action(path:string,body:unknown){setBusy(true);setError('');try{await api(path,body,user.csrf);setTick(n=>n+1);}catch(e){setError(e instanceof Error?e.message:'Request failed.');}finally{setBusy(false);}}
  const candidates=state?.jobs.filter(j=>j.operation==='train'&&j.status==='complete'&&j.model_sha256)??[];
  const active=state?.selection?.job;
  const working=state?.jobs.some(j=>j.status==='running');
  const workerRecent=!!state?.worker&&(loadedAt-state.worker.heartbeat<180||working);
  return <section className="panel quality-workbench"><p className="eyebrow">CALIBRATION WORKBENCH</p><h2>Measure before changing decisions</h2>
    <div className="quality-steps"><div><strong>1. Label</strong><span>Separate risk from mail type</span></div><div><strong>2. Compare</strong><span>Same human references for both engines</span></div><div><strong>3. Observe</strong><span>Explicit activation and rollback</span></div></div>
    <p className="muted">{workerRecent?'Research worker available.':'Research worker has not reported recently. Queued jobs wait for the offline worker.'} {active?`Shadow candidate: ${active.slice(0,8)}.`:'No managed shadow candidate selected.'}</p>
    <div className="quality-controls"><Button disabled={busy||!batch} variant="outline" onClick={()=>action('/quality/jobs',{batch,operation:'compare',candidate:null})}>Compare this sample</Button>
      <Button disabled={busy||!batch||purpose!=='development'} onClick={()=>action('/quality/jobs',{batch,operation:'train',candidate:null})}>Train a shadow candidate</Button>
      <label>Prepared candidate<select value={candidate} onChange={e=>setCandidate(e.target.value)}><option value="">Select a candidate</option>{candidates.map(j=><option key={j.id} value={j.id}>{new Date(j.created*1000).toLocaleString('en-GB')} · {j.id.slice(0,8)}</option>)}</select></label>
      <Button variant="outline" disabled={busy||!batch||!candidate} onClick={()=>action('/quality/jobs',{batch,operation:'evaluate',candidate})}>Evaluate on this sample</Button>
      <Button disabled={busy||!candidate||!state||candidate===active} onClick={()=>action('/quality/candidate',{revision:state!.revision,job:candidate})}>Use in observation</Button>
      <Button variant="outline" disabled={busy||!active||!state} onClick={()=>action('/quality/candidate',{revision:state!.revision,job:null})}>Disable shadow candidate</Button>
      <Button variant="outline" disabled={busy} onClick={()=>setTick(n=>n+1)}>Refresh jobs</Button></div>
    <p className="notice">Only development samples may be fitted. Regression and holdout samples remain excluded from training. Selecting an earlier prepared candidate rolls observation back through the same versioned configuration on both MX servers.</p>
    <p className="muted small">Final qualification requires an independent, recent test and confidence bounds. A shadow pilot does not grant permission to tag, reject or quarantine messages.</p>
    {error&&<p role="alert" className="error">{error}</p>}
    {!state?.jobs.length&&<p>No calibration jobs yet. Select a sample above to start a comparison.</p>}
    {state?.jobs.map(j=><details className="quality-job" key={j.id}><summary><strong>{j.operation==='train'?'Training':j.operation==='evaluate'?'Candidate evaluation':'Engine comparison'}</strong><span>{j.status.replaceAll('_',' ')} · {new Date(j.created*1000).toLocaleString('en-GB')}</span></summary>
      <p className="muted small">Job {j.id} · sample {j.batch.slice(0,8)}</p>
      {j.status==='queued'&&<Button variant="outline" disabled={busy} onClick={()=>action(`/quality/jobs/${j.id}/cancel`,{})}>Cancel queued job</Button>}
      {j.report&&<>{j.report.paired?<>
        <MetricTable report={j.report.paired} caption="Same human-labelled messages · recorded engine decisions · recipient overrides excluded"/>
        <p>{j.report.paired.coverage.paired} paired analyses · {j.report.paired.coverage.native_missing} missing NoiseFence decisions · {j.report.paired.coverage.rspamd_missing} missing Rspamd analyses. Missing results are excluded from this paired table.</p>
        {!j.report.paired.capture_comparison_supported&&<p className="notice">Only {j.report.paired.coverage.paired_spam} paired confirmed spams: too few to compare spam capture reliably. Zero false positives on a small sample does not establish production accuracy.</p>}
        {j.report.paired.profiles.length>1&&<p className="muted">This sample mixes {j.report.paired.profiles.length} detector profiles. Historical arrival results are not a replay of the current engines.</p>}
        <details><summary>Full-sample coverage and conservative policy baseline</summary><MetricTable report={j.report}/><p className="muted small">Missing analyses and incomplete non-antivirus NoiseFence decisions count as review here. This conservative baseline includes recipient overrides; it is not a paired comparison of recorded engine verdicts.</p></details>
      </>:<MetricTable report={j.report}/>}{j.report.coverage&&<p>{j.report.coverage.labelled??j.report.coverage.usable??0} usable or labelled observations · {j.report.coverage.unlabelled_or_uncertain??0} unlabelled or uncertain · {j.report.coverage.deleted_or_no_longer_authorized??0} missing from the original draw.</p>}
      {(j.report.paired?.campaigns??j.report.campaigns)&&<details><summary>Campaign-level comparison</summary><MetricTable report={(j.report.paired?.campaigns??j.report.campaigns)!} caption="One paired representative per campaign when paired results are available"/><p className="muted small">Conflicting labels are excluded before pairing. Missing campaign identities cannot establish independent samples.</p></details>}
      {j.report.mail_kind?.publicity&&<details><summary>Mail type: newsletter / promotion</summary><MetricTable report={{candidate:j.report.mail_kind.publicity}}/><p className="muted small">These are mail-type errors, separate from malicious-message errors.</p></details>}
      {!!j.report.legacy_score_calibration?.reliability.length&&<details><summary>Historical score reliability</summary><p className="muted small">The historical index is not a calibrated probability. Compare each score band with its human-labelled spam fraction.</p><div className="quality-table-scroll"><table className="quality-metrics"><thead><tr><th>Index band</th><th>Messages</th><th>Mean index</th><th>Human-labelled spam</th></tr></thead><tbody>{j.report.legacy_score_calibration.reliability.map(b=><tr key={b.bin}><th>{b.bin*10}–{b.bin*10+10}</th><td>{b.count}</td><td>{(b.mean_prediction*100).toFixed(1)}</td><td>{percent(b.spam_fraction)}</td></tr>)}</tbody></table></div></details>}
      {j.report.readiness&&<Folds value={j.report.readiness.risk}/>} {j.report.cohorts&&Object.entries(j.report.cohorts).map(([id,c])=><div key={id}><p>Detector cohort {id.slice(0,12)} · {c.messages} messages</p><Folds value={c.readiness}/></div>)}
      {j.report.pipeline_latency&&<p>Recorded total analysis p95: {j.report.pipeline_latency.p95_ms??'not measured'} ms · {j.report.pipeline_latency.samples} messages. Includes external services; native latency needs a separate benchmark.</p>}
      {j.report.acceptance&&<p>Shadow pilot: {j.report.acceptance.passes_pilot?'criteria met':'not qualified'} · Final confidence bounds: {j.report.acceptance.meets_final_confidence_bounds?'met':'not demonstrated'}.</p>}
      {j.report.native_parity&&<p>Rust prediction parity: {j.report.native_parity}.</p>}
      {j.report.error_code&&<p role="alert">Research job failed ({j.report.error_code}). No model was activated. Check the worker and dataset compatibility.</p>}
      {j.report.limitations?.map(note=><p className="muted small" key={note}>{note}</p>)}
      </>}
    </details>)}
  </section>;
}
