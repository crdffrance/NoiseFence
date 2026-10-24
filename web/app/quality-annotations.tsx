'use client';
import {useEffect,useState} from 'react';
import {Button} from '@/components/ui/button';
import {Input} from '@/components/ui/input';
import {api,type User} from './client';
import {CorrectionForm} from './correction-form';
import type {CorrectionScope} from './correction';
import {mailKinds,type Risk,type MailKind} from './quality-types';
export type Member = {id:string;created:number;sender:string;subject:string;risk:Risk|null;kind:MailKind|null;joint_observations:boolean};
type Draft = {risk:Risk|'';kind:MailKind|''};
function memberKey(member:Member){return `${member.id}:${member.risk}:${member.kind}`;}
function savedDraft(member:Member):Draft{return {risk:member.risk??'',kind:member.kind??''};}
function Annotation({member,user,onSaved,selected,onSelect,locked,onBusy,purpose,draft,onDraft,focusAfterSave}:{member:Member;user:User;onSaved:()=>void;selected:boolean;onSelect:()=>void;locked:boolean;onBusy:(busy:boolean)=>void;purpose:CorrectionScope;draft:Draft;onDraft:(draft:Draft)=>void;focusAfterSave:boolean}) {
  const {risk,kind}=draft;
  const setRisk=(risk:Risk|'')=>{onDraft({...draft,risk});setError('');};
  const setKind=(kind:MailKind|'')=>{onDraft({...draft,kind});setError('');};
  const [busy,setBusy]=useState(false),[error,setError]=useState('');
  async function save() {
    if (!risk || busy || locked) return;
    setBusy(true);onBusy(true);setError('');
    try {await api(`/messages/${member.id}/quality-label`,{risk,kind:kind || null},user.csrf);onSaved();}
    catch(e){setError(e instanceof Error ? e.message : "Correction not available.");}
    finally{setBusy(false);onBusy(false);}
  }
  return <article className={`quality-member${selected?" quality-member-selected":""}`}>
    <label className="quality-select"><input type="checkbox" checked={selected} disabled={locked||busy} onChange={onSelect} aria-label={`Select: ${member.subject || "Untitled message"}`} /> Select message</label>
    <div><h3>{member.subject || "(Not applicable)"}</h3><p>{member.sender}</p>
      <p className="muted small">{new Date(member.created*1000).toLocaleString("en-GB")}{!member.joint_observations && " · Analysis prior to the new protocol"}</p></div>
    <CorrectionForm scope={purpose} title="Annotate this message" compact focusOnMount={focusAfterSave}
      saved={member.risk?`${member.risk==='legitimate'?'Wanted':member.risk==='spam'?'Unwanted':'Uncertain'} · ${member.kind?mailKinds[member.kind]:'Mail type not specified'}`:'Not annotated'}
      onSave={()=>void save()} onReset={risk!==(member.risk??'')||kind!==(member.kind??'')?()=>{onDraft(savedDraft(member));setError('');}:undefined} disabled={locked||!risk} busy={busy} error={error}>
      <label>Risk<select aria-label={`Risk: ${member.subject || "Not applicable"}`} value={risk} disabled={busy||locked} onChange={e=>setRisk(e.target.value as Risk|'')}>
        <option value="">Select after verification</option><option value="legitimate">Wanted · Ham or Pub</option><option value="spam">Unwanted · spam or fraud</option><option value="uncertain">I cannot conclude</option>
      </select></label>
      <label>Type of mail, optional<select aria-label={`Type : ${member.subject || "Not applicable"}`} value={kind} disabled={busy||locked} onChange={e=>setKind(e.target.value as MailKind|'')}>
        <option value="">Undetermined</option>{Object.entries(mailKinds).map(([key,label])=><option value={key} key={key}>{label}</option>)}
      </select></label>
    </CorrectionForm>
  </article>;
}
export function AnnotationList({members,user,batch,onSaved,onBusy,onDirty,purpose,refreshing=false}:{members:Member[];user:User;batch:string;onSaved:(notice:string)=>void;onBusy:(busy:boolean)=>void;onDirty?:(dirty:boolean)=>void;purpose:CorrectionScope;refreshing?:boolean}) {
  const [selection,setSelection]=useState<string[]>([]),[query,setQuery]=useState(''),[unlabelled,setUnlabelled]=useState(false);
  const [risk,setRisk]=useState<Risk|''>(''),[kind,setKind]=useState<MailKind|''>('');
  const [overwrite,setOverwrite]=useState(false),[writing,setBusy]=useState(false),[error,setError]=useState(''),[bulkFocus,setBulkFocus]=useState(false);
  const [drafts,setDrafts]=useState<Record<string,Draft>>({}),[focusId,setFocusId]=useState('');
  const dirty=!!risk||!!kind||overwrite||members.some(member=>{const draft=drafts[memberKey(member)];return draft&&(draft.risk!==(member.risk??'')||draft.kind!==(member.kind??''));});
  useEffect(()=>{onDirty?.(dirty);return()=>onDirty?.(false);},[dirty,onDirty]);
  const busy=writing||refreshing;
  const visible=members.filter(m=>(!unlabelled||!m.risk)&&`${m.subject} ${m.sender}`.toLowerCase().includes(query.toLowerCase()));
  const setWorking=(value:boolean)=>{setBusy(value);onBusy(value);};
  async function apply() {
    if(!risk||!selection.length||busy)return;
    setWorking(true);setError('');setBulkFocus(false);
    try {
      const result=await api<{applied:number;skipped:number}>(`/quality/samples/${batch}/labels`,{ids:selection,risk,kind:kind||null,overwrite},user.csrf);
      setDrafts(previous=>Object.fromEntries(Object.entries(previous).filter(([key])=>!members.some(member=>selection.includes(member.id)&&(overwrite||!member.risk)&&memberKey(member)===key))));
      setSelection([]);setRisk('');setKind('');setOverwrite(false);setBulkFocus(true);
      onSaved(`${result.applied} annotations saved. ${result.skipped} existing annotations preserved.`);
    } catch(e) {setError(e instanceof Error?e.message:'Annotations could not be saved.');}
    finally {setWorking(false);}
  }
  return <>
    <section className="quality-bulk" aria-label="Bulk annotation">
      <h3>Annotate selected messages</h3>
      <div className="quality-controls">
        <label htmlFor="quality-bulk-search">Search this page<Input id="quality-bulk-search" value={query} disabled={busy} placeholder="Subject or sender" onChange={e=>{setQuery(e.target.value);setSelection([]);}} /></label>
        <label className="quality-select"><input type="checkbox" checked={unlabelled} disabled={busy} onChange={e=>{setUnlabelled(e.target.checked);setSelection([]);}} /> Unannotated only</label>
        <Button variant="outline" disabled={busy||!visible.length} onClick={()=>setSelection(visible.map(m=>m.id))}>Select visible ({visible.length})</Button>
        <Button variant="outline" disabled={busy||!selection.length} onClick={()=>setSelection([])}>Clear selection</Button>
      </div>
      <CorrectionForm focusOnMount={bulkFocus} scope={purpose} title="Classification for selected messages" onSave={()=>void apply()} disabled={busy||!risk||!selection.length} busy={writing} error={error} submitLabel={`Apply to ${selection.length} selected`}>
        <label>Risk for selected messages<select value={risk} disabled={busy} onChange={e=>setRisk(e.target.value as Risk|'')}><option value="">Choose a human verdict</option><option value="spam">Spam / fraud (unwanted)</option><option value="legitimate">Legitimate (wanted)</option><option value="uncertain">I cannot conclude</option></select></label>
        <label>Mail type for selected messages<select value={kind} disabled={busy} onChange={e=>setKind(e.target.value as MailKind|'')}><option value="">Keep existing type</option>{Object.entries(mailKinds).map(([key,label])=><option key={key} value={key}>{key==='newsletter'||key==='promotion'?`PUB · ${label}`:label}</option>)}</select></label>
      </CorrectionForm>
      <label className="quality-select"><input type="checkbox" checked={overwrite} disabled={busy} onChange={e=>setOverwrite(e.target.checked)} /> Replace my existing annotations on selected messages</label>
      <p className="muted small">Selection applies only to this page (up to 200 messages) and clears when you change page, sample or search. Choose risk separately from PUB: a newsletter may be wanted or unwanted. Messages already delivered are unchanged.</p>
      <output aria-live="polite">{selection.length} selected · {visible.length} shown on this page</output>
    </section>
    {!refreshing&&!visible.length&&<p>No messages match this page filter.</p>}
    <div className="quality-members">{visible.map(m=><Annotation key={memberKey(m)} draft={drafts[memberKey(m)]??savedDraft(m)} onDraft={draft=>setDrafts(previous=>({...previous,[memberKey(m)]:draft}))} focusAfterSave={focusId===m.id} purpose={purpose} member={m} user={user} selected={selection.includes(m.id)} onSelect={()=>setSelection(ids=>ids.includes(m.id)?ids.filter(id=>id!==m.id):[...ids,m.id])} locked={busy} onBusy={setWorking} onSaved={()=>{setFocusId(m.id);onSaved('Annotation saved.');}} />)}</div>
  </>;
}
