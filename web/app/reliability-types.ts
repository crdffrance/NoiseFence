export type Interval = { events:number; total:number; value:number; lower:number; upper:number } | null;
export type Metrics = { labelled:number; recall:Interval; false_positive_rate:Interval; precision:Interval; abstention:Interval };
export type Window = { messages:number; spam:number; review:number; legitimate:number; incomplete:number; disagreements:number; p95_ms:number|null; detector_status:Record<string,Record<string,number>> };
export type SymbolImpact = { source:string; hits:number; labelled_spam:number; labelled_legitimate:number; spam_decision_on_legitimate:number; absorbed:number; replayed:number; frozen_decision_changes:number; false_positives_avoided:number; detected_spam_lost:number };
export type Cohort = { messages:number; complete:number; native:number; risk_labels:number; targeted_labels:number; first_seen:number; last_seen:number; current_build:boolean; versions:string[] };
export type ProtonReport = { prefix:string; status:string; valid:boolean; tested_at:number|null; cases:{id:string;passed:boolean;evidence_present:boolean}[] };
export type Health = { status:string; database_revision?:number|null; minimum_age_seconds?:number|null; maximum_age_seconds?:number|null };
export type ReliabilityReport = {
  checked_at:number; status:string; observations:Window; last_24h:Window; reference:Window;
  quality_labels:Metrics; targeted_feedback:Metrics; unlabelled:number; saturated_scores:number;
  cohorts:Record<string,Cohort>; symbols:Record<string,SymbolImpact>;
  current_build_observations:number; current_protocol_observations:number; invalid_scans:number;
  cooccurrences:{a:string;b:string;hits:number}[];
  candidate_comparisons:{cohort_model:string;baseline:Metrics;candidate:Metrics}[];
  alerts:{code:string;level:string;detail:string;detector?:string}[]; limitations:string[];
  system?:{antivirus:Health;signatures:Health;proton:{mode:string;spam:ProtonReport;publicity:ProtonReport;note:string};quality_candidate_configured:boolean;native_bayes_configured:boolean};
};
export function rate(value:Interval) {
  if (!value || value.total<=0 || ![value.value,value.lower,value.upper].every(Number.isFinite)) return 'Non mesurable';
  const percent=(n:number)=>(n*100).toLocaleString('fr-FR',{maximumFractionDigits:2})+' %';
  return `${percent(value.value)} · IC 95 % ${percent(value.lower)}–${percent(value.upper)} (${value.events}/${value.total})`;
}
const statusLabels:Record<string,string>={complete:'Terminé',disabled:'Désactivé',not_configured:'Non configuré',not_run:'Non exécuté',unavailable:'Indisponible',busy:'Capacité atteinte',quota:'Quota atteint',stale:'Données trop anciennes',limited:'Partiel',unscannable:'Non analysable',malware:'Malware détecté',clean:'Aucune signature détectée',fresh:'Date récente',unknown:'État indéterminé',validated:'Validé',invalid:'Rapport invalide',mismatched:'Périmètre différent',incomplete:'À compléter',incompatible:'Incompatible',untrained:'Non entraîné'};
export function stateLabel(state:string){return statusLabels[state] || 'État indéterminé';}
export const detectorLabels:Record<string,string>={semantic:'Analyse sémantique',llm:'Second avis',antivirus:'Antivirus',signatures:'Signatures consultatives',vision:'OCR et QR',crdf:'CRDF',virustotal:'VirusTotal',url_feed:'Liste d’URL',redirects:'Redirections',native:'Moteur natif'};
export const protonLabels:Record<string,string>={dkim:'DKIM valide',spf_only:'SPF seul',dmarc_reject:'DMARC strict',mailing_list:'Liste de diffusion',forwarded:'Message transféré',international_subject:'Objet international',bypass:'Livraison directe',proton_internal:'Routage interne Proton'};
