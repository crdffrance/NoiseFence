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
  return ({not_listed:"IP not listed", listed:"IP listed", policy:"Policy list · without blocking vote", unavailable:"Check not available", skipped:"Unverified IP"} as Record<string,string>)[status] ?? "Unknown State";
}
export function rblIncident(incident: string | null): string {
  return ({dns:"DNS error", timeout:"Time exceeded", busy:"DNS capacity occupied", invalid_answer:"Unrecognized response code or provider error", unsupported_ip:"Private address, reserved address or IP family not supported"} as Record<string,string>)[incident ?? ''] ?? '';
}
