export const mailKinds = {
  conversation: 'Conversation', transactional: 'Facture / transaction',
  notification: 'Notification de service', newsletter: 'Newsletter',
  promotion: 'Publicité', other: 'Autre courrier',
} as const;
export type MailKind = keyof typeof mailKinds;
export type Risk = 'legitimate' | 'spam' | 'uncertain';
export function candidateLabel(status: string) {
  return ({complete:'Candidat évalué en observation',not_configured:'En attente d’un modèle candidat',
    incompatible:'Modèle incompatible avec ces contrôles',expired:'Modèle candidat expiré',
    missing_evidence:'Observations historiques absentes',unsupported_evidence:'Observations insuffisantes'} as Record<string,string>)[status] ?? 'État indisponible';
}
export type QualityReport = {
  candidate_status: string; complete_features: boolean;
  prediction?: {model:string;observation_only:boolean;risk_probability:number;risk:string;kind:MailKind;
    kind_probabilities:number[];contributions:{family:string;value:number}[]} | null;
  sender: {status:string;established:boolean;conflict:boolean;legitimate_campaigns:number;unwanted_campaigns:number;observed_days:number};
};
