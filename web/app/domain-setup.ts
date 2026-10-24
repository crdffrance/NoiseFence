import type { Gateway, Settings } from './admin';

export type DomainSetupDraft = {
  name: string;
  gatewayId: string;
  newGateway: Gateway;
  recipientMode: 'verify' | 'explicit';
  recipients: string;
};
export type DomainCheck = 'configuration' | 'dns' | 'recipient';
export type DomainCheckReport = {
  revision: number;
  domain: string;
  hostname: string;
  checked_at: number;
  draft: true;
  result: {
    check: DomainCheck;
    status: string;
    records?: { priority: number; host: string }[];
    truncated?: boolean;
    local_mx_present?: boolean;
    destination?: string;
    routes?: string[];
    data_sent?: boolean;
    loopback_test_allowed?: boolean;
  };
};
export const domainName = (name: string) => name.trim().toLowerCase();
const validDomain = (name: string) =>
  name.length > 0 &&
  name.length <= 253 &&
  name
    .split('.')
    .every(
      (part) =>
        part.length > 0 &&
        part.length <= 63 &&
        /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(part),
    );

export function setupProblem(
  settings: Settings,
  value: DomainSetupDraft,
  hostname: string,
  step: number,
): string | null {
  const name = domainName(value.name);
  if (!validDomain(name))
    return 'Enter a domain in ASCII or punycode format, without a URL or trailing dot.';
  if (settings.domains.some((d) => domainName(d.name) === name))
    return 'This domain is already in the draft. Edit its existing card.';
  if (settings.domains.length >= 100)
    return 'The maximum of 100 domains has been reached.';
  if (step === 0) return null;
  const gateway = value.gatewayId
    ? settings.gateways.find((g) => g.id === value.gatewayId)
    : value.newGateway;
  if (!gateway) return 'Choose an existing gateway or create a new one.';
  if (!gateway.name.trim() || gateway.name.trim().length > 100)
    return 'Enter a gateway name of at most 100 characters.';
  const hosts = gateway.hosts
    .map((h) => h.trim().toLowerCase())
    .filter(Boolean);
  if (
    hosts.length < 1 ||
    hosts.length > 8 ||
    !Number.isInteger(gateway.port) ||
    gateway.port < 1 ||
    gateway.port > 65535
  )
    return 'Enter 1–8 destination hosts and a port from 1 to 65535.';
  for (const route of hosts) {
    const parts = route.split(':');
    const host = parts[0].replace(/\.$/, '');
    if (
      parts.length > 2 ||
      !validDomain(host) ||
      (parts.length === 2 &&
        (!/^\d+$/.test(parts[1]) ||
          Number(parts[1]) < 1 ||
          Number(parts[1]) > 65535))
    )
      return 'Use destination hostnames, optionally followed by a port. URLs and credentials are not accepted.';
    if (
      host === domainName(hostname) ||
      host === name ||
      settings.domains.some((d) => domainName(d.name) === host)
    )
      return 'The destination must be the upstream mail host, not this MX or an accepted domain.';
  }
  if (!value.gatewayId && settings.gateways.length >= 100)
    return 'The maximum of 100 gateways has been reached.';
  if (step === 1) return null;
  if (value.recipientMode === 'explicit') {
    const addresses = value.recipients
      .split('\n')
      .map((a) => a.trim())
      .filter(Boolean);
    if (!addresses.length || addresses.length > 1000)
      return 'Enter 1–1000 authorized addresses, one per line.';
    if (
      addresses.some(
        (a) =>
          a.includes('\r') ||
          a.slice(a.lastIndexOf('@') + 1).toLowerCase() !== name ||
          a.lastIndexOf('@') < 1,
      )
    )
      return 'Every address must belong to the new domain. The server will validate its full syntax.';
  }
  return null;
}

export function prepareDomain(
  settings: Settings,
  value: DomainSetupDraft,
): Settings {
  const gateway = value.gatewayId
    ? undefined
    : {
        ...value.newGateway,
        name: value.newGateway.name.trim(),
        hosts: value.newGateway.hosts
          .map((h) => h.trim().toLowerCase())
          .filter(Boolean),
      };
  return {
    ...settings,
    gateways: gateway ? [...settings.gateways, gateway] : settings.gateways,
    domains: [
      ...settings.domains,
      {
        name: domainName(value.name),
        gateway: gateway?.id ?? value.gatewayId,
        enabled: true,
        accept_all_recipients: value.recipientMode === 'verify',
        recipient_verification:
          value.recipientMode === 'verify'
            ? {
                timeout_ms: 8000,
                positive_cache_seconds: 60,
                negative_cache_seconds: 30,
              }
            : null,
        recipients:
          value.recipientMode === 'explicit'
            ? value.recipients
                .split('\n')
                .map((a) => a.trim())
                .filter(Boolean)
            : [],
        aliases: {},
      },
    ],
  };
}

export function checkSummary(report: DomainCheckReport): string {
  const { check, status } = report.result;
  if (check === 'configuration')
    return status === 'valid'
      ? 'Draft configuration validated. It has not been applied.'
      : 'Configuration validation did not complete.';
  if (check === 'dns') {
    if (status === 'null_mx')
      return 'A Null MX record advertises that this domain does not accept mail. Correct DNS before cutover.';
    if (status === 'unavailable')
      return 'MX lookup unavailable. Check domain existence, DNS and connectivity; delivery is not verified.';
    if (status === 'no_records')
      return 'No explicit MX records were returned. Publish the intended MX records after delivery testing.';
    return report.result.local_mx_present
      ? 'This server hostname appears in public MX records. This does not verify delivery or the other MX servers.'
      : 'Current MX records do not include this server hostname. Keep the current route until delivery testing is complete.';
  }
  if (status === 'accepted')
    return 'The destination accepted RCPT TO. No message was sent; inbox placement and DATA acceptance still need a delivery test.';
  if (status === 'unknown')
    return 'The destination explicitly rejected this recipient as nonexistent.';
  return 'Recipient verification unavailable. The destination may be unreachable, reject the test envelope or defer verification. This does not prove the address is missing.';
}
