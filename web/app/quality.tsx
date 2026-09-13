'use client';
import { useEffect, useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { api, type User } from './client';
import { candidateLabel, mailKinds, mailKindLabel, type SampleReadiness, type MailKind, type Risk, type QualityReport } from './quality-types';

type Batch = {id:string;created:number;since:number;until:number;domain:string;population:number;selected:number;available:number;labelled:number};
type Member = {id:string;created:number;sender:string;subject:string;risk:Risk|null;kind:MailKind|null;joint_observations:boolean};
export function QualityDetails({report}:{report:QualityReport}) {
  return <section className="panel message-diagnostics">
    <h2>Risk and type of mail</h2>
    <p>{candidateLabel(report.candidate_status)}</p>
    {report.prediction && <>
      <p><strong>{report.prediction.risk === 'spam' ? "Likely spam" : report.prediction.risk === 'legitimate' ? "Likely legitimate" : "Needs review"}</strong>
        {' · '}{mailKindLabel(report.prediction.kind)}</p>
      <p className="muted small">Model {report.prediction.model} · Probability of estimated risk {(report.prediction.risk_probability*100).toFixed(1)} % in the context assessed.</p>
    </>}
    <p className="muted small">This candidate analysis does not alter the classification applied or the delivery.</p>
    <p>{report.sender.established ? "Authenticated correspondence with a validated history." : report.sender.conflict ? "Contradictory corrections in correspondent's history." : "Historical confidence not established."}</p>
    {report.sender.status === 'complete' && <p className="muted small">{report.sender.legitimate_campaigns} legitimate campaigns, {report.sender.unwanted_campaigns} undesirable · {report.sender.observed_days} No security checks are bypassed.</p>}
    {report.sender.behavior && <p className="muted small">Contact person&apos;s habits: {report.sender.behavior.status==='complete'
      ? [report.sender.behavior.new_recipient && "recipient not met",report.sender.behavior.new_link_domain && "new area of link",report.sender.behavior.new_request && "new type of application"].filter(Boolean).join(' · ') || "no changes observed"
      : report.sender.behavior.status==='insufficient_history'?"insufficient annotated history":"comparison not available"}. Advisory observation; a novelty does not prove fraud.</p>}
  </section>;
}
function Annotation({member,user,onSaved}:{member:Member;user:User;onSaved:()=>void}) {
  const [risk,setRisk]=useState<Risk|''>(member.risk ?? '');
  const [kind,setKind]=useState<MailKind|''>(member.kind ?? '');
  const [busy,setBusy]=useState(false),[error,setError]=useState('');
  async function save() {
    if (!risk) return;
    setBusy(true);setError('');
    try {await api(`/messages/${member.id}/quality-label`,{risk,kind:kind || null},user.csrf);onSaved();}
    catch(e){setError(e instanceof Error ? e.message : "Correction not available.");}
    finally{setBusy(false);}
  }
  return <article className="quality-member">
    <div><h3>{member.subject || "(Not applicable)"}</h3><p>{member.sender}</p>
      <p className="muted small">{new Date(member.created*1000).toLocaleString("en-GB")}{!member.joint_observations && " · Analysis prior to the new protocol"}</p></div>
    <div className="quality-annotation">
      <label>Risk<select aria-label={`Risk: ${member.subject || "Not applicable"}`} value={risk} disabled={busy} onChange={e=>setRisk(e.target.value as Risk|'')}>
        <option value="">Select after verification</option><option value="legitimate">Legitimate</option><option value="spam">Spam / fraud</option><option value="uncertain">I can&apos;t conclude.</option>
      </select></label>
      <label>Type of mail, optional<select aria-label={`Type : ${member.subject || "Not applicable"}`} value={kind} disabled={busy} onChange={e=>setKind(e.target.value as MailKind|'')}>
        <option value="">Undetermined</option>{Object.entries(mailKinds).map(([key,label])=><option value={key} key={key}>{label}</option>)}
      </select></label>
      <Button disabled={busy || !risk} onClick={save}>{busy?"Saving…":member.risk?"Update":"Validate"}</Button>
    </div>{error && <p role="alert" className="error">{error}</p>}
  </article>;
}
export function QualityConsole({user}:{user:User}) {
  const [batches,setBatches]=useState<Batch[]>([]),[selected,setSelected]=useState('');
  const [loaded,setLoaded]=useState<{id:string;revision:number;offset:number;members:Member[];readiness?:SampleReadiness}>({id:'',revision:0,offset:0,members:[]});
  const [offset,setOffset]=useState(0);
  const [days,setDays]=useState(7),[count,setCount]=useState(50),[domain,setDomain]=useState('');
  const [busy,setBusy]=useState(false),[error,setError]=useState(''),[revision,setRevision]=useState(0);
  const [configured,setConfigured]=useState(false);
  const [observationStart,setObservationStart]=useState<number|null>(null);
  useEffect(()=>{
    const controller=new AbortController();
    api<{batches:Batch[];candidate_configured:boolean;observation_start:number|null}>('/quality/samples',undefined,undefined,{signal:controller.signal})
      .then(result=>{if(!controller.signal.aborted){setBatches(result.batches);setConfigured(result.candidate_configured);setObservationStart(result.observation_start);}})
      .catch(e=>{if(!controller.signal.aborted)setError(e.message);});
    return ()=>controller.abort();
  },[revision]);
  useEffect(()=>{
    const controller=new AbortController();
    if(!selected)return;
    Promise.all([api<Member[]>(`/quality/samples/${selected}?offset=${offset}`,undefined,undefined,{signal:controller.signal}),
      api<SampleReadiness>(`/quality/samples/${selected}/readiness`,undefined,undefined,{signal:controller.signal})])
      .then(([members,readiness])=>{if(!controller.signal.aborted)setLoaded({id:selected,revision,offset,members,readiness});})
      .catch(e=>{if(!controller.signal.aborted){setError(e.message);setLoaded({id:selected,revision,offset,members:[]});}});
    return ()=>controller.abort();
  },[selected,revision,offset]);
  async function create() {
    setBusy(true);setError('');
    try {const until=Math.floor(Date.now()/1000);
      const result=await api<{id:string}>('/quality/samples',{since:Math.max(until-days*86400,observationStart ?? until),until,count,domain:domain.trim().toLowerCase()},user.csrf);
      setSelected(result.id);setOffset(0);setRevision(x=>x+1);
    }catch(e){setError(e instanceof Error?e.message:"Creation not available.");}
    finally{setBusy(false);}
  }
  const current=batches.find(b=>b.id===selected);
  const loading=!!selected && (loaded.id!==selected || loaded.revision!==revision || loaded.offset!==offset);
  const members=selected && !loading ? loaded.members : [];
  return <div className="quality-console">
    <section className="panel"><p className="eyebrow">QUALITY OF THE FILTER</p><h1>Learning with verified decisions</h1>
      <p>Evaluate a random sample among your accessible messages. The selection ignores the filter score and remains frozen.</p>
      <p className="muted">{configured?"A candidate model is configured for observation.":"The engine is collecting observations. No candidate model is configured yet."}</p>
      <p className="muted small">{observationStart ? `The period begins as soon as possible on ${new Date(observationStart*1000).toLocaleString("en-GB")}, at the beginning of this collection.` : "Waiting for the first message analyzed with the current engine. Refresh after arrival."}</p>
      <div className="quality-controls">
        <label>Period<select value={days} onChange={e=>setDays(Number(e.target.value))}><option value={1}>Last 24 hours</option><option value={7}>Last 7 days</option><option value={14}>Last 14 days</option><option value={29}>Last 29 days</option></select></label>
        <label>Messages<select value={count} onChange={e=>setCount(Number(e.target.value))}><option value={25}>25</option><option value={50}>50</option><option value={100}>100</option><option value={200}>200</option></select></label>
        <label htmlFor="quality-domain">Domain (optional)<Input id="quality-domain" value={domain} onChange={e=>setDomain(e.target.value)} placeholder="All my accessible domains" /></label>
        <Button disabled={busy || observationStart===null} onClick={create}>{busy?"Drawing in progress...":"Create a sample"}</Button>
        <Button variant="outline" disabled={busy} onClick={()=>setRevision(x=>x+1)}>Refresh</Button>
      </div>{error && <p className="error" role="alert">{error}</p>}
    </section>
    <section className="panel"><h2>Samples retained</h2>
      {!batches.length?<p>No sample. Create one to start validation.</p>:<label>Sample<select value={selected} onChange={e=>{setSelected(e.target.value);setOffset(0);}}><option value="">Select a sample</option>{batches.map(b=><option key={b.id} value={b.id}>{new Date(b.created*1000).toLocaleString("en-GB")} · {b.labelled}/{b.selected} annotated{b.domain?` · ${b.domain}`:''}</option>)}</select></label>}
      {current && <><p>{current.selected} messages drawn from {current.population} · {current.available} still accessible · {current.labelled} annotated.</p>
        <p className="notice">Check the original in your mailbox before answering. The subject alone is insufficient. If unsure, choose “I cannot conclude”.</p>
        <p className="muted small">The scores are hidden here to avoid influencing your judgment. Annotations feed candidates; they do not change messages already delivered.</p></>}
      {current && current.available > 200 && <div className="quality-controls">
        <Button variant="outline" disabled={loading || offset===0} onClick={()=>setOffset(x=>Math.max(0,x-200))}>Prev</Button>
        <span>Page {Math.floor(offset/200)+1} / {Math.ceil(current.available/200)}</span>
        <Button variant="outline" disabled={loading || offset+200>=current.available} onClick={()=>setOffset(x=>x+200)}>Next</Button>
      </div>}
      {current && !loading && loaded.readiness && <div className="notice">
        <p>{loaded.readiness.risk_with_observations} risk annotations with usable observations · {loaded.readiness.kind_with_observations} usable mail-type annotations.</p>
        <p>You can validate the risk without knowing the type of mail. Uncertain answers are not transformed into legitimate examples.</p>
        {loaded.readiness.missing_or_incompatible_observations>0 && <p>{loaded.readiness.missing_or_incompatible_observations} messages do not have the necessary observations for this pipeline. Their corrections remain.</p>}
        {loaded.readiness.detector_cohorts>1 && <p>This batch covers several versions of the controls; they will have to be evaluated separately.</p>}
        <p className="muted small">These accounts describe the available data. The diversity of the examples and their separation over time remain to be verified before any learning.</p>
      </div>}
      {loading && <output>Loading messages...</output>}
      <div className="quality-members">{members.map(m=><Annotation key={`${m.id}:${revision}`} member={m} user={user} onSaved={()=>setRevision(x=>x+1)}/>)}</div>
    </section>
  </div>;
}
