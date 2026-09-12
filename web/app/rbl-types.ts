export type EarlyRbl = {
  version: string;
  elapsed_ms: number;
  listed_providers: number;
  minimum_providers: number;
  would_block: boolean;
  requested_action: 'observe' | 'defer' | 'reject';
  effective_action: 'observe' | 'defer' | 'reject';
  checks: {
    id: string;
    provider: string;
    status: string;
    codes: string[];
    incident: string | null;
    cached: boolean;
  }[];
};
export function rblStatus(status: string): string {
  return ({not_listed:'IP non listée', listed:'IP listée', policy:'Liste de politique · sans vote de blocage', unavailable:'Vérification indisponible', skipped:'IP non vérifiée'} as Record<string,string>)[status] ?? 'État inconnu';
}
export function rblIncident(incident: string | null): string {
  return ({dns:'Erreur DNS', timeout:'Délai dépassé', busy:'Capacité DNS occupée', invalid_answer:'Code de réponse non reconnu ou erreur du fournisseur', unsupported_ip:'Adresse privée, réservée ou famille IP non prise en charge'} as Record<string,string>)[incident ?? ''] ?? '';
}
