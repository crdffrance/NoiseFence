export const mailKinds = {
  conversation: 'Conversation', transactional: 'Facture / transaction',
  notification: 'Notification de service', newsletter: 'Newsletter',
  promotion: 'Publicité', other: 'Autre courrier',
} as const;
export type MailKind = keyof typeof mailKinds;
export type Risk = 'legitimate' | 'spam' | 'uncertain';
export function mailKindLabel(kind: string) {
  return (mailKinds as Record<string,string>)[kind] ?? 'Type indéterminé';
}
export type SampleReadiness = {
  selected:number;available:number;labelled:number;risk_labels:number;kind_labels:number;
  risk_with_observations:number;kind_with_observations:number;
  missing_or_incompatible_observations:number;detector_cohorts:number;
  training_validated:false;observation_only:true;
};
export function candidateLabel(status: string) {
  return ({complete:'Candidat évalué en observation',not_configured:'En attente d’un modèle candidat',
    incompatible:'Modèle incompatible avec ces contrôles',expired:'Modèle candidat expiré',
    missing_evidence:'Observations historiques absentes',unsupported_evidence:'Observations insuffisantes'} as Record<string,string>)[status] ?? 'État indisponible';
}
export type QualityReport = {
  candidate_status: string; complete_features: boolean;
  prediction?: {model:string;observation_only:boolean;risk_probability:number;risk:string;kind:MailKind|'unavailable';kind_status?:string;
    kind_probabilities:number[];contributions:{family:string;value:number}[]} | null;
  sender: {behavior?:{status:string;new_recipient:boolean;new_link_domain:boolean;new_request:boolean;observation_only:boolean}|null;status:string;established:boolean;conflict:boolean;legitimate_campaigns:number;unwanted_campaigns:number;observed_days:number};
};
