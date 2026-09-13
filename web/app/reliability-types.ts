export type Interval = { events:number; total:number; value:number; lower:number; upper:number } | null;
export type Metrics = { labelled:number; recall:Interval; false_positive_rate:Interval; precision:Interval; abstention:Interval };
export type Coverage = {providers:Record<string,{messages:number;checked:number;cached:number;omitted:number;requests:number;http_status:Record<string,number>;failures:Record<string,number>;retry_after_max_seconds:number}>;redirect_details:Record<string,number>;redirect_categories:Record<string,number>;redirect_http_status:Record<string,number>;redirects_complete:number;redirects_omitted:number};
export type Misses = {messages:number;classified_legitimate:number;review:number;context:Record<string,number>};
export type Window = { coverage?:Coverage; messages:number; spam:number; review:number; legitimate:number; incomplete:number; disagreements:number; p95_ms:number|null; detector_status:Record<string,Record<string,number>> };
export type SymbolImpact = { source:string; hits:number; labelled_spam:number; labelled_legitimate:number; spam_decision_on_legitimate:number; absorbed:number; replayed:number; frozen_decision_changes:number; false_positives_avoided:number; detected_spam_lost:number };
export type Cohort = { messages:number; complete:number; native:number; risk_labels:number; targeted_labels:number; first_seen:number; last_seen:number; current_build:boolean; versions:string[] };
export type ProtonReport = { prefix:string; status:string; valid:boolean; tested_at:number|null; cases:{id:string;passed:boolean;evidence_present:boolean}[] };
export type Health = { status:string; database_revision?:number|null; minimum_age_seconds?:number|null; maximum_age_seconds?:number|null };
export type ReliabilityReport = {
  current_build_last_24h?:Window; missed_diagnostics?:{quality:Misses;targeted:Misses};
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
  if (!value || value.total<=0 || ![value.value,value.lower,value.upper].every(Number.isFinite)) return "Not measurable";
  const percent=(n:number)=>(n*100).toLocaleString("en-GB",{maximumFractionDigits:2})+' %';
  return `${percent(value.value)} · 95% CI ${percent(value.lower)}–${percent(value.upper)} (${value.events}/${value.total})`;
}
const statusLabels:Record<string,string>={complete:"Completed",disabled:"Disabled",not_configured:"Not configured",not_run:"Not implemented",unavailable:"Unavailable",busy:"Capacity achieved",quota:"Quota reached",stale:"Data too old",limited:"Partial",unscannable:"Not analysable",malware:"Malware detected",clean:"No signature detected",fresh:"Recent date",unknown:"Undetermined State",validated:"Validated",invalid:"Invalid report",mismatched:"Different perimeter",incomplete:"To be completed",incompatible:'Incompatible',untrained:"Untrained"};
export function stateLabel(state:string){return statusLabels[state] || "Undetermined State";}
export const detectorLabels:Record<string,string>={semantic:"Semantic analysis",llm:"Second opinion",antivirus:'Antivirus',signatures:"Advisory signatures",vision:"OCR and QR",crdf:'CRDF',virustotal:'VirusTotal',url_feed:"List of URLs",redirects:'Redirections',native:"Native engine"};
export const protonLabels:Record<string,string>={dkim:"Valid DKIM",spf_only:"SPF alone",dmarc_reject:'DMARC strict',mailing_list:"Mailing list",forwarded:"Message transferred",international_subject:"International subject",bypass:"Direct delivery",proton_internal:"Proton Internal Routing"};

const details:Record<string,string>={unsafe_url:"URL outside the authorized perimeter",forbidden_address:"Prohibited network address",dns:"DNS resolution not available",network:"Unavailable connection",http_status:"HTTP response not exploitable",invalid_redirect:"Ambiguous redirection",loop:"Redirection loop",hop_limit:"Number of redirections achieved",body_limit:"Page too large",encoding:"Encoding not supported",client_script:"JavaScript dependent destination",deadline:"Time limit for monitoring achieved",busy:"Control capacity achieved"};
export function detailLabel(value:string){return details[value] || "Limit not recognized";}
const diagnostics:Record<string,string>={analysis_incomplete:"Partial analysis",extraction_incomplete:"Partial extraction",authentication_unavailable:"Authentication unavailable",provider_incomplete:"Incomplete external reputation",redirect_incomplete:"Unsolved Link Destination",decision_disagreement:"Disagreement between opinions",corroboration_absent:"Evidence of confirmation missing"};
export function diagnosticLabel(value:string){return diagnostics[value] || "Unrecognized context";}
