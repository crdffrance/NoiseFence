'use client';
import { useCallback, useEffect, useRef, useState } from 'react';
import { api, type User } from './client';
import { Button } from '@/components/ui/button';

type Version = { version: string; engine_build: string; node: string };
type Update = { status: string; latest_version?: string; release_url?: string; checked_at: number; next_check_at: number };
const messages: Record<string, string> = {
  available: 'A newer stable release is available.',
  same_version: 'The version number matches the latest stable release. Custom builds may differ.',
  ahead: 'This installation is ahead of the published stable release.',
  development: 'This is a development version. Compare the release notes before upgrading.',
  no_public_release: 'No public stable release was found. Update status is unknown.',
  unavailable: 'GitHub could not be checked. Update status is unknown.',
};
export function SoftwareStatus({ user }: { user: User }) {
  const [version, setVersion] = useState<Version | null>(null);
  const [versionError, setVersionError] = useState(false);
  const [update, setUpdate] = useState<Update | null>(null);
  const [automatic, setAutomatic] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const pending = useRef(false);
  const nextCheck = useRef(0);
  const preference = `noisefence:update-check:${user.username}`;
  useEffect(() => {
    const controller = new AbortController();
    api<Version>('/system/version', undefined, undefined, { signal: controller.signal })
      .then(value => {
        if (controller.signal.aborted) return;
        setVersion(value);
        try { setAutomatic(user.admin && localStorage.getItem(preference) === 'enabled'); } catch { /* Manual checking remains available. */ }
      })
      .catch(() => { if (!controller.signal.aborted) setVersionError(true); });
    return () => controller.abort();
  }, [preference, user.admin]);
  const check = useCallback(async () => {
    if (pending.current) return;
    pending.current = true;
    setBusy(true); setError('');
    try {
      const result = await api<Update>('/admin/updates/check', {}, user.csrf);
      setUpdate(result);
      nextCheck.current = result.next_check_at * 1000;
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Update check unavailable.');
      nextCheck.current = Date.now() + 6 * 3600 * 1000;
    } finally { pending.current = false; setBusy(false); }
  }, [user.csrf]);
  useEffect(() => {
    if (!user.admin || !automatic) return;
    const run = () => { if (document.visibilityState === 'visible' && Date.now() >= nextCheck.current) void check(); };
    run();
    const timer = setInterval(run, 60_000);
    document.addEventListener('visibilitychange', run);
    return () => { clearInterval(timer); document.removeEventListener('visibilitychange', run); };
  }, [automatic, user.admin, check]);
  return <div className="software-status">
    <div><strong>{version ? `NoiseFence ${version.version}` : versionError ? 'Version unavailable' : 'Loading version…'}</strong></div>
    {version && <div className="muted" title={`Serving API node: ${version.node}\nEngine build: ${version.engine_build}`}>{version.node} · build {version.engine_build.slice(0, 12)}</div>}
    {user.admin && <details>
      <summary>Software updates{update?.status === 'available' ? ' · Available' : ''}</summary>
      <p>Check published stable releases on GitHub. Installation remains a server operation.</p>
      <label className="software-auto-check"><input type="checkbox" checked={automatic} onChange={e => {
        const enabled = e.target.checked;
        setAutomatic(enabled);
        try { localStorage.setItem(preference, enabled ? 'enabled' : 'disabled'); } catch { /* Session-only preference. */ }
      }} /> Automatically check while this console is open</label>
      <p className="muted">Every six hours, on this browser. Only public release metadata is requested.</p>
      <Button variant="outline" size="sm" disabled={busy} onClick={() => void check()}>{busy ? 'Checking…' : 'Check for updates'}</Button>
      {error && <p role="alert">{error}</p>}
      {update && <output><p>{messages[update.status] ?? 'Update status is unknown.'}</p>
        {update.release_url && <a href={update.release_url} target="_blank" rel="noopener noreferrer">Release notes · {update.latest_version}</a>}
        <p className="muted">Checked {new Date(update.checked_at * 1000).toLocaleString('en-GB')}. Results are cached for six hours.</p>
      </output>}
    </details>}
  </div>;
}
