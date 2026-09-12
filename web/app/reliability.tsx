'use client';
import { useEffect,useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { api } from './client';
import { rate,stateLabel,detectorLabels,protonLabels,type Metrics,type ReliabilityReport,type ProtonReport,type Health } from './reliability-types';
function Measures({title,data}:{title:string;data:Metrics}) {
  return <section className="panel"><h2>{title}</h2><p>{data.labelled} messages annotés</p><dl className="reliability-measures">
    <div><dt>Rappel</dt><dd>{rate(data.recall)}</dd></div><div><dt>Faux positifs</dt><dd>{rate(data.false_positive_rate)}</dd></div>
    <div><dt>Précision</dt><dd>{rate(data.precision)}</dd></div><div><dt>À vérifier</dt><dd>{rate(data.abstention)}</dd></div>
  </dl><p className="muted small">Intervalles de Wilson à 95 %. Ils décrivent ces annotations ; leur sélection et les campagnes corrélées limitent toute généralisation au trafic.</p></section>;
}
function Proton({report}:{report:ProtonReport}) {
  return <div><h3>{report.prefix} · {stateLabel(report.status)}</h3><ul className="reliability-checklist">{report.cases.map(c=><li key={c.id}>
    <span>{protonLabels[c.id] || 'Cas de validation'}</span><strong>{c.passed && c.evidence_present?'Documenté':'À vérifier'}</strong>
  </li>)}</ul></div>;
}
function Freshness({title,value}:{title:string;value:Health}) {
  return <div><h3>{title}</h3><p>{stateLabel(value.status)}</p>
    {value.database_revision!=null && <p className="muted small">Révision annoncée : {value.database_revision}</p>}
    {value.minimum_age_seconds!=null && value.maximum_age_seconds!=null && <p className="muted small">Âge de la date annoncée : {Math.floor(value.minimum_age_seconds/3600)} à {Math.ceil(value.maximum_age_seconds/3600)} h. Fuseau inconnu ; cet état ne certifie pas le jeu exact de signatures chargé.</p>}
  </div>;
}
export function ReliabilityConsole() {
  const [days,setDays]=useState(7),[domain,setDomain]=useState('');
  const [request,setRequest]=useState({days:7,domain:'',revision:0});
  const [report,setReport]=useState<ReliabilityReport|null>(null),[error,setError]=useState(''),[busy,setBusy]=useState(true);
  const [symbolSearch,setSymbolSearch]=useState('');
  useEffect(()=>{
    const controller=new AbortController();
    api<ReliabilityReport>(`/quality/reliability?days=${request.days}&domain=${encodeURIComponent(request.domain)}`,undefined,undefined,{signal:controller.signal,cache:'no-store'})
      .then(r=>{if(!controller.signal.aborted){setReport(r);setError('');setBusy(false);}})
      .catch(e=>{if(!controller.signal.aborted){setReport(null);setError(e instanceof Error?e.message:'Bilan indisponible.');setBusy(false);}});
    return ()=>controller.abort();
  },[request]);
  function refresh(){setBusy(true);setReport(null);setError('');setRequest({days,domain:domain.trim().toLowerCase(),revision:request.revision+1});}
  const symbols=Object.entries(report?.symbols ?? {}).filter(([id])=>id.toLowerCase().includes(symbolSearch.toLowerCase())).sort((a,b)=>b[1].spam_decision_on_legitimate-a[1].spam_decision_on_legitimate || b[1].hits-a[1].hits);
  return <div className="quality-console reliability-console">
    <section className="panel"><p className="eyebrow">FIABILITÉ DU FILTRE</p><h1>Mesurer avant de modifier</h1><p>Un bilan de vos messages accessibles, des corrections humaines et de la disponibilité des contrôles.</p>
      <div className="quality-controls"><label>Période<select value={days} onChange={e=>setDays(Number(e.target.value))}><option value={1}>24 heures</option><option value={7}>7 jours</option><option value={14}>14 jours</option><option value={29}>29 jours</option></select></label>
        <label htmlFor="reliability-domain">Domaine, facultatif<Input id="reliability-domain" value={domain} onChange={e=>setDomain(e.target.value)} placeholder="Tous mes domaines accessibles"/></label>
        <Button disabled={busy} onClick={refresh}>Actualiser le bilan</Button></div>
      {error && <p role="alert" className="error">{error}</p>}{busy && <output>Calcul du bilan…</output>}
      {report && <p className="muted small">Calculé le {new Date(report.checked_at*1000).toLocaleString('fr-FR')} · {report.status==='limited'?'Historique partiel':'Historique parcouru'} · Aucun réglage modifié.</p>}
    </section>
    {report && <>
      {report.alerts.length>0 && <section className="panel" aria-label="Points à examiner"><h2>Points à examiner</h2>{report.alerts.map((a,i)=><p className={a.level==='warning'?'notice':'muted'} key={`${a.code}:${i}`}>{a.detector && <strong>{detectorLabels[a.detector] || 'Contrôle'} : </strong>}{a.detail}</p>)}</section>}
      <section className="panel"><h2>Trafic observé</h2><div className="reliability-grid">
        {[[report.observations.messages,'messages'],[report.observations.spam,'classés indésirables'],[report.observations.review,'à vérifier'],[report.observations.incomplete,'analyses incomplètes'],[report.observations.disagreements,'avis contradictoires'],[report.observations.p95_ms==null?'—':`${report.observations.p95_ms} ms`,'latence d’analyse p95']].map(([n,label])=><div className="reliability-stat" key={String(label)}><strong>{n}</strong><span>{label}</span></div>)}
      </div><p className="muted small">Le classement enregistré ne prouve ni le caractère réel du message ni son dossier d’arrivée chez Proton. La latence mesure le parcours enregistré, dont les contrôles externes ; elle ne constitue pas un benchmark à caches chauds.</p></section>
      <div className="reliability-columns"><Measures title="Annotations de qualité" data={report.quality_labels}/><Measures title="Corrections ciblées" data={report.targeted_feedback}/></div>
      <section className="panel"><h2>Disponibilité des contrôles</h2><p className="muted">Sur les dernières 24 heures du bilan. Une absence de contrôle ne vaut pas un résultat négatif.</p>
        <div className="reliability-table"><table><thead><tr><th>Contrôle</th><th>États enregistrés</th></tr></thead><tbody>{Object.entries(report.last_24h.detector_status).map(([name,states])=><tr key={name}><td>{detectorLabels[name] || 'Contrôle'}</td><td>{Object.entries(states).map(([s,n])=>`${stateLabel(s)} : ${n}`).join(' · ')}</td></tr>)}</tbody></table></div>
        {!report.last_24h.messages && <p>Aucun message récent dans ce périmètre.</p>}
      </section>
      {report.system && <section className="panel"><h2>État des services de signatures</h2><div className="reliability-columns"><Freshness title="Antivirus" value={report.system.antivirus}/><Freshness title="Signatures consultatives" value={report.system.signatures}/></div></section>}
      <section className="panel"><h2>Collecte pour la calibration</h2><p>{report.current_build_observations} observations liées au moteur courant · {report.current_protocol_observations} au protocole courant · {report.unlabelled} sans annotation exploitable.</p>
        <p className="muted">Chaque groupe ci-dessous lie les mêmes contrôles, modèles et paramètres. Les anciennes corrections restent utiles pour l’audit ; elles ne sont pas converties en observations nouvelles. Créez les lots dans « Qualité du filtre » et vérifiez les originaux dans votre messagerie.</p>
        <div className="reliability-table"><table><thead><tr><th>Groupe de collecte</th><th>Messages</th><th>Complets</th><th>Annotations qualité</th><th>Période</th></tr></thead><tbody>{Object.entries(report.cohorts).sort((a,b)=>b[1].last_seen-a[1].last_seen).map(([id,c])=><tr key={id}><td><code title={id}>{id.slice(0,12)}</code>{c.current_build?' · moteur courant':''}</td><td>{c.messages}</td><td>{c.complete}</td><td>{c.risk_labels}</td><td>{new Date(c.first_seen*1000).toLocaleDateString('fr-FR')} – {new Date(c.last_seen*1000).toLocaleDateString('fr-FR')}</td></tr>)}</tbody></table></div>
        <p className="notice">L’activation exige encore un test indépendant, séparé par dates et campagnes, avec les objectifs et leurs intervalles de confiance. Aucune activation automatique.</p>
      </section>
      <section className="panel"><h2>Apport des règles</h2><p>Les lignes sont triées par erreurs sur des messages annotés légitimes, puis par fréquence. Plusieurs règles peuvent décrire le même événement.</p>
        <label htmlFor="reliability-symbol">Rechercher un symbole<Input id="reliability-symbol" value={symbolSearch} onChange={e=>setSymbolSearch(e.target.value)} placeholder="Ex. model_contribution, NF_CREDENTIALS"/></label>
        <div className="reliability-table"><table><thead><tr><th>Symbole</th><th>Occurrences</th><th>Annotés spam / légitimes</th><th>Retrait simulé : décisions changées</th><th>Faux positifs évités / spams perdus</th></tr></thead><tbody>{symbols.slice(0,50).map(([id,s])=><tr key={id}><td><code>{id}</code>{s.source==='native_observation' && <small>Observation native · {s.absorbed} regroupements</small>}</td><td>{s.hits}</td><td>{s.labelled_spam} / {s.labelled_legitimate}</td><td>{s.source==='native_observation'?'Consultatif':`${s.frozen_decision_changes} / ${s.replayed} relectures`}</td><td>{s.source==='native_observation'?'Non simulé':`${s.false_positives_avoided} / ${s.detected_spam_lost}`}</td></tr>)}</tbody></table></div>
        <p className="muted small">{Math.min(50,symbols.length)} / {symbols.length} symboles affichés. Le retrait concerne le poids, avec les preuves et avis déjà enregistrés. Il ne prédit pas un nouveau parcours d’analyse ni les actions par destinataire.</p>
        <details><summary>Signaux présents ensemble</summary><ul>{report.cooccurrences.slice(0,15).map(p=><li key={`${p.a}:${p.b}`}><code>{p.a}</code> + <code>{p.b}</code> : {p.hits}</li>)}</ul><p className="muted small">Une cooccurrence ne démontre pas l’indépendance ou la causalité.</p></details>
      </section>
      <section className="panel"><h2>Comparaisons candidates enregistrées</h2>{!report.candidate_comparisons.length?<p>Aucun couple de prédictions annotées disponible.</p>:report.candidate_comparisons.map(c=><details key={c.cohort_model}><summary><code>{c.cohort_model.slice(0,12)}</code> · {c.baseline.labelled} messages</summary><div className="reliability-columns"><Measures title="Décision appliquée" data={c.baseline}/><Measures title="Candidat en observation" data={c.candidate}/></div></details>)}<p className="muted small">Cette comparaison porte sur les cas annotés et pris en charge par le candidat. Elle ne remplace pas une évaluation indépendante de sa couverture et de ses erreurs.</p></section>
      {report.system && <section className="panel"><h2>Validation du marquage Proton</h2><p>Politique : {report.system.proton.mode==='observe'?'observation':report.system.proton.mode}. {report.system.proton.note}</p><div className="reliability-columns"><Proton report={report.system.proton.spam}/><Proton report={report.system.proton.publicity}/></div><p className="muted small">Pour chaque cas : comparer arrivée directe, relais sans modification et relais avec préfixe ; conserver les en-têtes reçus et le dossier constaté. Les rapports restent soumis au contrôle de configuration.</p></section>}
      <section className="panel"><details><summary>Périmètre et limites du bilan</summary><ul>{report.limitations.map(text=><li key={text}>{text}</li>)}</ul></details></section>
    </>}
  </div>;
}
