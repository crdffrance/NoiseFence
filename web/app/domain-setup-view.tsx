'use client';
import { useEffect, useRef, useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { api, type User } from './client';
import type { Settings } from './admin';
import {
  checkSummary,
  domainName,
  prepareDomain,
  setupProblem,
  type DomainCheck,
  type DomainCheckReport,
  type DomainSetupDraft,
} from './domain-setup';

const steps = ['Domain', 'Destination', 'Recipients', 'Check & prepare'];
export function DomainSetup({
  settings,
  revision,
  hostname,
  user,
  onPrepared,
  onClose,
}: {
  settings: Settings;
  revision: number;
  hostname: string;
  user: User;
  onPrepared: (settings: Settings) => void;
  onClose: () => void;
}) {
  const [value, setValue] = useState<DomainSetupDraft>(() => ({
    name: '',
    gatewayId: settings.gateways[0]?.id ?? '',
    newGateway: {
      id: `gateway-${crypto.randomUUID()}`,
      name: '',
      hosts: [],
      port: 25,
    },
    recipientMode: 'verify',
    recipients: '',
  }));
  const [step, setStep] = useState(0),
    [recipient, setRecipient] = useState('');
  const [running, setRunning] = useState<{
    key: string;
    check: DomainCheck;
  } | null>(null);
  const [failure, setFailure] = useState<{
    key: string;
    message: string;
  } | null>(null);
  const [reports, setReports] = useState<
    Partial<Record<DomainCheck, { key: string; report: DomainCheckReport }>>
  >({});
  const heading = useRef<HTMLHeadingElement>(null),
    request = useRef<AbortController | null>(null);
  const proposed = prepareDomain(settings, value);
  const key = JSON.stringify({ settings: proposed, revision });
  const requestKey = JSON.stringify({ key, recipient });
  const busy = running?.key === requestKey ? running.check : null;
  const error = failure?.key === requestKey ? failure.message : '';
  useEffect(() => {
    heading.current?.focus();
  }, [step]);
  useEffect(() => () => request.current?.abort(), [requestKey]);
  const problem = setupProblem(settings, value, hostname, step);
  const reportFor = (check: DomainCheck) =>
    reports[check]?.key === (check === 'recipient' ? requestKey : key)
      ? reports[check]?.report
      : undefined;
  const validated = reportFor('configuration')?.result.status === 'valid';
  async function run(check: DomainCheck) {
    const focused = document.activeElement;
    const controller = new AbortController();
    request.current = controller;
    setRunning({ key: requestKey, check });
    setFailure(null);
    setReports((previous) => {
      const next = { ...previous };
      delete next[check];
      return next;
    });
    try {
      const report = await api<DomainCheckReport>(
        '/admin/domains/check',
        {
          revision,
          settings: proposed,
          domain: domainName(value.name),
          check,
          recipient: check === 'recipient' ? recipient.trim() : null,
        },
        user.csrf,
        { signal: controller.signal },
      );
      if (!controller.signal.aborted)
        setReports((old) => ({
          ...old,
          [check]: { key: check === 'recipient' ? requestKey : key, report },
        }));
    } catch (e) {
      if (!controller.signal.aborted)
        setFailure({ key: requestKey, message: (e as Error).message });
    } finally {
      if (!controller.signal.aborted)
        setRunning((current) => (current?.key === requestKey ? null : current));
      if (
        !controller.signal.aborted &&
        focused instanceof HTMLElement &&
        focused.isConnected &&
        document.activeElement === document.body
      )
        requestAnimationFrame(() => focused.focus());
    }
  }
  return (
    <section
      className="panel domain-setup"
      aria-labelledby="domain-setup-title"
    >
      <div className="domain-setup-heading">
        <div>
          <p className="eyebrow">GUIDED SETUP · UNSAVED</p>
          <h2 ref={heading} tabIndex={-1} id="domain-setup-title">
            Add a domain — {steps[step]}
          </h2>
        </div>
        <Button variant="ghost" onClick={onClose}>
          Cancel setup
        </Button>
      </div>
      <ol className="domain-setup-steps" aria-label="Setup progress">
        {steps.map((label, i) => (
          <li key={label} aria-current={i === step ? 'step' : undefined}>
            <span>{i + 1}</span>
            {label}
          </li>
        ))}
      </ol>
      <p className="muted">
        Prepare a domain and its destination without changing live routing.
        Review and apply the full draft after setup.
      </p>
      <fieldset disabled={!!busy} className="domain-setup-fields">
        {step === 0 && (
          <label className="field" htmlFor="setup-domain-name">
            Domain name
            <Input
              id="setup-domain-name"
              value={value.name}
              placeholder="example.org"
              autoComplete="off"
              spellCheck={false}
              onChange={(e) => setValue({ ...value, name: e.target.value })}
            />
            <small>
              The domain and its mailboxes must already exist at your mail
              provider. This does not publish DNS records or create mailboxes.
            </small>
          </label>
        )}
        {step === 1 && (
          <>
            <label className="field">
              Delivery gateway
              <select
                value={value.gatewayId}
                onChange={(e) =>
                  setValue({ ...value, gatewayId: e.target.value })
                }
              >
                {settings.gateways.map((g) => (
                  <option key={g.id} value={g.id}>
                    {g.name}
                  </option>
                ))}
                <option value="">Create a gateway</option>
              </select>
            </label>
            {!value.gatewayId ? (
              <div className="form-grid">
                <label className="field" htmlFor="setup-gateway-name">
                  Gateway name
                  <Input
                    id="setup-gateway-name"
                    value={value.newGateway.name}
                    placeholder="Primary mail provider"
                    onChange={(e) =>
                      setValue({
                        ...value,
                        newGateway: {
                          ...value.newGateway,
                          name: e.target.value,
                        },
                      })
                    }
                  />
                </label>
                <label className="field" htmlFor="setup-gateway-port">
                  Destination port
                  <Input
                    id="setup-gateway-port"
                    type="number"
                    min={1}
                    max={65535}
                    value={value.newGateway.port}
                    onChange={(e) =>
                      setValue({
                        ...value,
                        newGateway: {
                          ...value.newGateway,
                          port: Number(e.target.value),
                        },
                      })
                    }
                  />
                </label>
                <label className="field wide">
                  Destination hosts
                  <textarea
                    rows={3}
                    value={value.newGateway.hosts.join('\n')}
                    placeholder="inbound.provider.example"
                    spellCheck={false}
                    onChange={(e) =>
                      setValue({
                        ...value,
                        newGateway: {
                          ...value.newGateway,
                          hosts: e.target.value.split('\n'),
                        },
                      })
                    }
                  />
                  <small>
                    One host per line, in priority order. Use your provider’s
                    explicit receiving servers, not your domain’s public MX
                    route. TLS certificate verification is required.
                  </small>
                </label>
              </div>
            ) : (
              <p className="notice">
                Destination:{' '}
                <code>
                  {settings.gateways
                    .find((g) => g.id === value.gatewayId)
                    ?.hosts.join(' → ')}
                </code>
                . Existing gateway settings remain unchanged.
              </p>
            )}
          </>
        )}
        {step === 2 && (
          <>
            <label className="field">
              Recipient policy
              <select
                value={value.recipientMode}
                onChange={(e) =>
                  setValue({
                    ...value,
                    recipientMode: e.target
                      .value as DomainSetupDraft['recipientMode'],
                  })
                }
              >
                <option value="verify">
                  Use destination mailboxes — verify during SMTP
                </option>
                <option value="explicit">
                  Only explicitly declared addresses
                </option>
              </select>
            </label>
            {value.recipientMode === 'verify' ? (
              <p className="notice">
                Receive *@{domainName(value.name)} without declaring every
                address. A destination 550 5.1.1 refuses an unknown mailbox;
                unavailable verification defers acceptance with 451. No fallback
                mailbox is configured. Every MX must support recipient
                verification.
              </p>
            ) : (
              <label className="field">
                Authorized addresses
                <textarea
                  rows={5}
                  value={value.recipients}
                  placeholder={`mail@${domainName(value.name)}`}
                  onChange={(e) =>
                    setValue({ ...value, recipients: e.target.value })
                  }
                />
                <small>
                  One full address per line. Keep this list aligned with your
                  provider. Other addresses will be refused; declared addresses
                  are not probed on every message.
                </small>
              </label>
            )}
            <p className="muted">
              Aliases and advanced verification limits can be adjusted in the
              domain card after preparing the draft.
            </p>
          </>
        )}
        {step === 3 && (
          <>
            <dl className="domain-setup-facts">
              <div>
                <dt>Domain</dt>
                <dd>{domainName(value.name)}</dd>
              </div>
              <div>
                <dt>Destination</dt>
                <dd>
                  {proposed.gateways
                    .find((g) => g.id === proposed.domains.at(-1)?.gateway)
                    ?.hosts.join(' → ')}
                </dd>
              </div>
              <div>
                <dt>Recipients</dt>
                <dd>
                  {value.recipientMode === 'verify'
                    ? 'Destination verification; no fallback'
                    : 'Explicit address list; no fallback'}
                </dd>
              </div>
              <div>
                <dt>Global filtering</dt>
                <dd>Existing policy preserved</dd>
              </div>
            </dl>
            <div className="domain-setup-checks">
              <div>
                <h3>1. Validate the draft</h3>
                <p>
                  Validate the complete configuration against the installed
                  policy and model constraints.
                </p>
                <Button
                  variant="outline"
                  onClick={() => void run('configuration')}
                >
                  Validate draft
                </Button>
                <CheckResult report={reportFor('configuration')} />
              </div>
              <div>
                <h3>2. Inspect public DNS</h3>
                <p>
                  Look up this domain’s MX records from this console host.
                  Maximum five seconds; no DNS changes.
                </p>
                <Button variant="outline" onClick={() => void run('dns')}>
                  Check MX records
                </Button>
                <CheckResult report={reportFor('dns')} />
              </div>
              <div>
                <h3>3. Check a destination recipient</h3>
                <p>
                  Connect to the explicit route with verified TLS, an empty
                  envelope sender and one RCPT TO. The check ends before DATA,
                  within eight seconds.
                </p>
                <label className="field" htmlFor="setup-recipient">
                  Test recipient
                  <Input
                    id="setup-recipient"
                    value={recipient}
                    placeholder={`mail@${domainName(value.name)}`}
                    spellCheck={false}
                    onChange={(e) => setRecipient(e.target.value)}
                  />
                </label>
                <Button
                  variant="outline"
                  disabled={!recipient.trim()}
                  onClick={() => void run('recipient')}
                >
                  Check recipient without sending mail
                </Button>
                <CheckResult report={reportFor('recipient')} />
              </div>
            </div>
            <p className="notice">
              Before changing public MX records, apply the configuration, wait
              for activation on every MX, then send an authorized test message
              through each server and confirm delivery in the destination
              mailbox. These checks do not validate mailbox placement, ARC/DKIM
              forwarding or the second server’s network access. Installation
              checks for TLS, PTR, MTA-STS and TLS-RPT remain separate.
            </p>
          </>
        )}
      </fieldset>
      {problem && (
        <p className="muted" id="domain-setup-problem">
          {problem}
        </p>
      )}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      <output className="muted">{busy ? 'Check in progress…' : ''}</output>
      <div className="domain-setup-actions">
        {step > 0 && (
          <Button
            variant="outline"
            disabled={!!busy}
            onClick={() => setStep(step - 1)}
          >
            Back
          </Button>
        )}
        {step < 3 ? (
          <Button
            disabled={!!problem || !!busy}
            aria-describedby={problem ? 'domain-setup-problem' : undefined}
            onClick={() => setStep(step + 1)}
          >
            Continue
          </Button>
        ) : (
          <Button
            disabled={!!problem || !!busy || !validated}
            onClick={() => onPrepared(proposed)}
          >
            Add to draft for review
          </Button>
        )}
      </div>
    </section>
  );
}
function CheckResult({ report }: { report?: DomainCheckReport }) {
  if (!report) return null;
  return (
    <div className="domain-check-result" aria-live="polite">
      <p>{checkSummary(report)}</p>
      {!!report.result.records?.length && (
        <ul>
          {report.result.records.map((r) => (
            <li key={`${r.priority}:${r.host}`}>
              {r.priority} · <code>{r.host}</code>
            </li>
          ))}
        </ul>
      )}
      {report.result.truncated && (
        <p>Only the first 32 records are displayed.</p>
      )}
      {report.result.destination && (
        <p>
          Canonical destination: <code>{report.result.destination}</code>
        </p>
      )}
      {report.result.loopback_test_allowed && (
        <p>
          Isolated test configuration: loopback plaintext is permitted. This is
          not production TLS validation.
        </p>
      )}
      <small>
        Checked {new Date(report.checked_at * 1000).toLocaleString()} on{' '}
        {report.hostname}. Draft revision {report.revision}.
      </small>
    </div>
  );
}
