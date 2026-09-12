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
    <h2>Risque et type de courrier</h2>
    <p>{candidateLabel(report.candidate_status)}</p>
    {report.prediction && <>
      <p><strong>{report.prediction.risk === 'spam' ? 'Spam probable' : report.prediction.risk === 'legitimate' ? 'Légitime probable' : 'À vérifier'}</strong>
        {' · '}{mailKindLabel(report.prediction.kind)}</p>
      <p className="muted small">Modèle {report.prediction.model} · probabilité de risque estimée {(report.prediction.risk_probability*100).toFixed(1)} % dans le contexte évalué.</p>
    </>}
    <p className="muted small">Cette analyse candidate ne modifie ni le classement appliqué ni la livraison.</p>
    <p>{report.sender.established ? 'Correspondant authentifié avec un historique validé.' : report.sender.conflict ? 'Corrections contradictoires dans l’historique du correspondant.' : 'Confiance historique non établie.'}</p>
    {report.sender.status === 'complete' && <p className="muted small">{report.sender.legitimate_campaigns} campagnes légitimes, {report.sender.unwanted_campaigns} indésirables · {report.sender.observed_days} jours distincts. Aucun contrôle de sécurité n’est contourné.</p>}
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
    catch(e){setError(e instanceof Error ? e.message : 'Correction indisponible.');}
    finally{setBusy(false);}
  }
  return <article className="quality-member">
    <div><h3>{member.subject || '(Sans objet)'}</h3><p>{member.sender}</p>
      <p className="muted small">{new Date(member.created*1000).toLocaleString('fr-FR')}{!member.joint_observations && ' · Analyse antérieure au nouveau protocole'}</p></div>
    <div className="quality-annotation">
      <label>Risque<select aria-label={`Risque : ${member.subject || 'sans objet'}`} value={risk} disabled={busy} onChange={e=>setRisk(e.target.value as Risk|'')}>
        <option value="">Choisir après vérification</option><option value="legitimate">Légitime</option><option value="spam">Spam / fraude</option><option value="uncertain">Je ne peux pas conclure</option>
      </select></label>
      <label>Type de courrier, facultatif<select aria-label={`Type : ${member.subject || 'sans objet'}`} value={kind} disabled={busy} onChange={e=>setKind(e.target.value as MailKind|'')}>
        <option value="">Indéterminé</option>{Object.entries(mailKinds).map(([key,label])=><option value={key} key={key}>{label}</option>)}
      </select></label>
      <Button disabled={busy || !risk} onClick={save}>{busy?'Enregistrement…':member.risk?'Mettre à jour':'Valider'}</Button>
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
    }catch(e){setError(e instanceof Error?e.message:'Création indisponible.');}
    finally{setBusy(false);}
  }
  const current=batches.find(b=>b.id===selected);
  const loading=!!selected && (loaded.id!==selected || loaded.revision!==revision || loaded.offset!==offset);
  const members=selected && !loading ? loaded.members : [];
  return <div className="quality-console">
    <section className="panel"><p className="eyebrow">QUALITÉ DU FILTRE</p><h1>Apprendre avec des décisions vérifiées</h1>
      <p>Évaluez un échantillon tiré au sort parmi vos messages accessibles. La sélection ignore le score du filtre et reste figée.</p>
      <p className="muted">{configured?'Un modèle candidat est configuré en observation.':'Le moteur collecte les observations ; aucun nouveau modèle n’est encore configuré.'}</p>
      <p className="muted small">{observationStart ? `La période commence au plus tôt le ${new Date(observationStart*1000).toLocaleString('fr-FR')}, au début de cette collecte.` : 'En attente du premier message analysé avec le moteur courant. Actualisez après son arrivée.'}</p>
      <div className="quality-controls">
        <label>Période<select value={days} onChange={e=>setDays(Number(e.target.value))}><option value={1}>Dernières 24 heures</option><option value={7}>7 derniers jours</option><option value={14}>14 derniers jours</option><option value={29}>29 derniers jours</option></select></label>
        <label>Messages<select value={count} onChange={e=>setCount(Number(e.target.value))}><option value={25}>25</option><option value={50}>50</option><option value={100}>100</option><option value={200}>200</option></select></label>
        <label htmlFor="quality-domain">Domaine, facultatif<Input id="quality-domain" value={domain} onChange={e=>setDomain(e.target.value)} placeholder="Tous mes domaines accessibles" /></label>
        <Button disabled={busy || observationStart===null} onClick={create}>{busy?'Tirage en cours…':'Créer un échantillon'}</Button>
        <Button variant="outline" disabled={busy} onClick={()=>setRevision(x=>x+1)}>Actualiser</Button>
      </div>{error && <p className="error" role="alert">{error}</p>}
    </section>
    <section className="panel"><h2>Échantillons conservés</h2>
      {!batches.length?<p>Aucun échantillon. Créez-en un pour commencer la validation.</p>:<label>Échantillon<select value={selected} onChange={e=>{setSelected(e.target.value);setOffset(0);}}><option value="">Choisir un échantillon</option>{batches.map(b=><option key={b.id} value={b.id}>{new Date(b.created*1000).toLocaleString('fr-FR')} · {b.labelled}/{b.selected} annotés{b.domain?` · ${b.domain}`:''}</option>)}</select></label>}
      {current && <><p>{current.selected} messages tirés parmi {current.population} · {current.available} encore accessibles · {current.labelled} annotés.</p>
        <p className="notice">Vérifiez l’original dans votre boîte avant de répondre. L’objet seul ne suffit pas. En cas de doute, choisissez « Je ne peux pas conclure ».</p>
        <p className="muted small">Les scores sont masqués ici pour éviter d’influencer votre jugement. Les annotations alimentent des candidats ; elles ne changent pas les messages déjà livrés.</p></>}
      {current && current.available > 200 && <div className="quality-controls">
        <Button variant="outline" disabled={loading || offset===0} onClick={()=>setOffset(x=>Math.max(0,x-200))}>Précédents</Button>
        <span>Page {Math.floor(offset/200)+1} / {Math.ceil(current.available/200)}</span>
        <Button variant="outline" disabled={loading || offset+200>=current.available} onClick={()=>setOffset(x=>x+200)}>Suivants</Button>
      </div>}
      {current && !loading && loaded.readiness && <div className="notice">
        <p>{loaded.readiness.risk_with_observations} annotations de risque avec observations exploitables · {loaded.readiness.kind_with_observations} annotations de type exploitables.</p>
        <p>Vous pouvez valider le risque sans connaître le type de courrier. Les réponses incertaines ne sont pas transformées en exemples légitimes.</p>
        {loaded.readiness.missing_or_incompatible_observations>0 && <p>{loaded.readiness.missing_or_incompatible_observations} messages n’ont pas les observations nécessaires à ce pipeline. Leurs corrections restent conservées.</p>}
        {loaded.readiness.detector_cohorts>1 && <p>Ce lot couvre plusieurs versions des contrôles ; elles devront être évaluées séparément.</p>}
        <p className="muted small">Ces comptes décrivent les données disponibles. La diversité des exemples et leur séparation dans le temps restent à vérifier avant tout apprentissage.</p>
      </div>}
      {loading && <output>Chargement des messages…</output>}
      <div className="quality-members">{members.map(m=><Annotation key={`${m.id}:${revision}`} member={m} user={user} onSaved={()=>setRevision(x=>x+1)}/>)}</div>
    </section>
  </div>;
}
