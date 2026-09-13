export type UrlResolutionReport = {
  version: string;
  settings_sha256: string;
  elapsed_ms: number;
  omitted: number;
  local_inventory_available?: boolean | null;
  chains: {
    source_sha256: string;
    complete: boolean;
    detail: string | null;
    hops: { url_sha256: string; site: string; code: number }[];
  }[];
};

export function UrlResolutionDetails({
  report,
}: {
  report?: UrlResolutionReport | null;
}) {
  if (!report) return null;
  return (
    <section aria-label="Link redirections">
      <h3>Link redirections</h3>
      <p className="muted small">
        {report.chains.length} link(s) · {report.elapsed_ms} ms. Domains displayed without private paths or settings. A destination reached does not mean that the link is safe.
      </p>
      {report.local_inventory_available === false && (
        <p className="notice">
          Server network inventory unavailable. Check service restrictions; URL visits remain suspended.
        </p>
      )}
      {report.omitted > 0 && (
        <p className="notice">
          At least {report.omitted} additional link(s) skipped because of the check limit.
        </p>
      )}
      <ol>
        {report.chains.map((chain, index) => (
          <li key={`${chain.source_sha256}-${index}`}>
            <strong>
              Link {index + 1} ·{' '}
              {chain.complete
                ? 'HTTP destination reached'
                : "Incomplete redirect chain"}
            </strong>
            <p>
              {chain.hops
                .map((hop) => `${hop.site} (${hop.code})`)
                .join(' → ') || "No HTTP response received"}
            </p>
            {chain.detail && (
              <p>
                {(
                  {
                    unsafe_url: "Unauthorized address or protocol.",
                    forbidden_address:
                      "Access to an internal, reserved or excluded address blocked.",
                    dns: "DNS resolution unavailable or ambiguous.",
                    network: "Connection or TLS verification failed.",
                    http_status:
                      "The remote server prevented completion of the redirect chain.",
                    invalid_redirect:
                      "Redirection absent, ambiguous or invalid.",
                    loop: "Redirect loop.",
                    hop_limit: "Redirect limit reached.",
                    body_limit:
                      "Page too large or complex for this control.",
                    encoding: "Page encoding not supported.",
                    client_script:
                      "The page contains JavaScript; script navigation is not executed.",
                    deadline: "Time limit reached.",
                    busy: "Check capacity exhausted.",
                  } as Record<string, string>
                )[chain.detail] || "Check incomplete."}
              </p>
            )}
          </li>
        ))}
      </ol>
      <p className="muted small">
        The domains encountered are included in the reputation reports above, depending on the active connectors and their quotas. The exact URLs are compared to the local phishing database when it is enabled and available.
      </p>
    </section>
  );
}
