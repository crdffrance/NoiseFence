'use client';
import { useEffect, useRef, useState } from 'react';
import { Button } from '@/components/ui/button';
import { api } from './client';
export type ModelFile = { sha256: string; size: number };
export type ModelPreview = {
  revision: number;
  installed_sha256: string;
  installation_sha256: string;
  installed: Record<string, ModelFile>;
  installation: Record<string, ModelFile>;
  qualification: 'not_evaluated';
};
export function ModelManifest({
  value,
  sourceLabel = 'Server installation',
}: {
  value: Pick<ModelPreview, 'installed' | 'installation'>;
  sourceLabel?: string;
}) {
  const slots = [
    ...new Set([
      ...Object.keys(value.installed),
      ...Object.keys(value.installation),
    ]),
  ].sort();
  return (
    <div className="quality-table-scroll">
      <table className="quality-metrics">
        <caption>Model files for this draft · SHA-256 identities</caption>
        <thead>
          <tr>
            <th>Model slot</th>
            <th>Installed</th>
            <th>{sourceLabel}</th>
          </tr>
        </thead>
        <tbody>
          {slots.map((slot) => (
            <tr key={slot}>
              <th>{slot}</th>
              {[value.installed[slot], value.installation[slot]].map(
                (file, i) => (
                  <td key={i}>
                    {file ? (
                      <>
                        <code title={file.sha256}>
                          {file.sha256.slice(0, 16)}…
                        </code>
                        <small>{file.size.toLocaleString('en-GB')} bytes</small>
                      </>
                    ) : (
                      'Not included'
                    )}
                  </td>
                ),
              )}
            </tr>
          ))}
        </tbody>
      </table>
      {!slots.length && <p>No local model files are selected by this draft.</p>}
    </div>
  );
}
export function ModelSources({
  revision,
  settings,
  csrf,
  disabled,
  coordinated,
  selected,
  onSelect,
}: {
  revision: number;
  settings: unknown;
  csrf: string;
  disabled: boolean;
  coordinated: boolean;
  selected: string | null;
  onSelect: (digest: string | null) => void;
}) {
  const key = JSON.stringify([revision, settings]);
  const [response, setResponse] = useState<{
    key: string;
    value: ModelPreview | null;
    error: string;
  } | null>(null);
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const request = useRef<AbortController | null>(null);
  const preview = response?.key === key ? response.value : null;
  const error = response?.key === key ? response.error : '';
  const busy = busyKey === key;
  useEffect(() => () => request.current?.abort(), [key]);
  async function inspect() {
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    setBusyKey(key);
    setResponse(null);
    onSelect(null);
    try {
      const value = await api<ModelPreview>(
        '/admin/cluster/models/preview',
        { revision, settings },
        csrf,
        { signal: controller.signal },
      );
      if (!controller.signal.aborted) setResponse({ key, value, error: '' });
    } catch (e) {
      if (!controller.signal.aborted)
        setResponse({ key, value: null, error: (e as Error).message });
    } finally {
      if (!controller.signal.aborted) setBusyKey(null);
    }
  }
  return (
    <section className="management-card">
      <h2>Local model files</h2>
      <p>
        Settings saves keep the installed model files. Replacing a file on the
        server does not automatically select it. Disabling a detector excludes
        its files from the next policy; enabling an excluded model requires an
        explicit selection.
      </p>
      <p className="small muted">
        To select new models, review the files configured on the server and
        include their exact digest in your next settings save. Model bytes and
        validation reports are verified before installation. This does not
        demonstrate detection accuracy or change observation mode.
      </p>
      {!coordinated && (
        <p className="notice">
          Enable coordinated changes on the MX servers page before selecting
          model files here.
        </p>
      )}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      <Button
        variant="outline"
        disabled={disabled || busy || !coordinated}
        onClick={() => void inspect()}
      >
        {busy ? 'Inspecting files…' : 'Preview server model files'}
      </Button>
      {preview && (
        <>
          <ModelManifest value={preview} />
          <p className="small muted">
            Quality qualification: not evaluated by this preview. A matching
            digest establishes file identity, not filtering performance.
          </p>
          <label className="setting-toggle">
            <input
              type="checkbox"
              disabled={disabled || busy}
              checked={selected === preview.installation_sha256}
              onChange={(e) =>
                onSelect(e.target.checked ? preview.installation_sha256 : null)
              }
            />
            Use these exact server model files in the next save
          </label>
          {selected && (
            <output className="notice">
              Model selection is a draft. Review and save settings to stage it
              across the MXs.
            </output>
          )}
        </>
      )}
    </section>
  );
}
