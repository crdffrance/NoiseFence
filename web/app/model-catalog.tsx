'use client';
import { useEffect, useRef, useState } from 'react';
import { Button } from '@/components/ui/button';
import { api } from './client';
import { ModelManifest, type ModelFile } from './model-sources';

type Shadow = { job: string | null; sha256: string | null } | null;
export type RetainedSet = {
  id: string;
  label: string;
  created: number;
  source_build: string;
  source_revision: number;
  files: Record<string, ModelFile>;
  quality_candidate: Shadow;
};
type Catalog = { entries: RetainedSet[]; max_sets: number; max_bytes: number };
type Preview = {
  id: string;
  revision: number;
  installation_sha256: string;
  installed: Record<string, ModelFile>;
  installation: Record<string, ModelFile>;
  quality_candidate: Shadow;
  qualification: { whole_pipeline: string; fusion_validation: string };
};
export type CatalogChoice = {
  id: string;
  digest: string;
  quality_candidate: Shadow;
};

export function CatalogQualification({
  value,
}: {
  value: Preview['qualification'];
}) {
  const details: Record<string, string> = {
    not_applicable: 'This set has no fusion model.',
    missing: 'No fusion validation report is included.',
    report_contract_valid:
      'The bundled fusion report satisfies its model-bound validation contract today. This does not independently certify the whole pipeline or compatibility with this draft.',
    invalid_or_stale:
      'The bundled fusion report is invalid or stale. It cannot authorize decision mode.',
  };
  return (
    <div className="notice">
      <strong>Whole-pipeline qualification: not evaluated</strong>
      <p>
        {Object.hasOwn(details, value.fusion_validation)
          ? details[value.fusion_validation]
          : 'Fusion validation status is unavailable.'}
      </p>
      <p>
        Preparation checks model compatibility on every MX. Observation and
        existing activation requirements still apply.
      </p>
    </div>
  );
}

export function CatalogTable({
  entries,
  disabled,
  onPreview,
  onRemove,
}: {
  entries: RetainedSet[];
  disabled: boolean;
  onPreview: (id: string) => void;
  onRemove: (id: string) => void;
}) {
  if (!entries.length) return <p>No model sets are retained yet.</p>;
  return (
    <div className="quality-table-scroll">
      <table className="quality-metrics">
        <caption>Explicitly retained model sets</caption>
        <thead>
          <tr>
            <th>Set</th>
            <th>Provenance</th>
            <th>Size</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {entries.map((entry) => (
            <tr key={entry.id}>
              <th>
                {entry.label}
                <small>
                  <code title={entry.id}>{entry.id.slice(0, 16)}…</code>
                </small>
              </th>
              <td>
                {entry.source_build}
                <small>Source revision {entry.source_revision}</small>
              </td>
              <td>
                {Object.values(entry.files)
                  .reduce((sum, file) => sum + file.size, 0)
                  .toLocaleString('en-GB')}{' '}
                bytes
              </td>
              <td>
                <Button
                  variant="outline"
                  disabled={disabled}
                  onClick={() => onPreview(entry.id)}
                >
                  Preview for this draft
                </Button>{' '}
                <Button
                  variant="outline"
                  disabled={disabled}
                  onClick={() => onRemove(entry.id)}
                >
                  Remove retained copy
                </Button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function ModelCatalog({
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
  onSelect: (choice: CatalogChoice | null) => void;
}) {
  const key = JSON.stringify([revision, settings]);
  const [catalog, setCatalog] = useState<{
    revision: number;
    value: Catalog;
  } | null>(null);
  const [refresh, setRefresh] = useState(0);
  const [label, setLabel] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [preview, setPreview] = useState<{
    key: string;
    value: Preview;
  } | null>(null);
  const request = useRef<AbortController | null>(null);
  const current = preview?.key === key ? preview.value : null;
  const items = catalog?.revision === revision ? catalog.value : null;
  useEffect(() => () => request.current?.abort(), [key]);
  useEffect(() => {
    if (!coordinated) return;
    const controller = new AbortController();
    api<Catalog>('/admin/cluster/models/catalog', undefined, undefined, {
      signal: controller.signal,
    })
      .then((value) => {
        if (!controller.signal.aborted) {
          setCatalog({ revision, value });
          setError('');
        }
      })
      .catch((e) => {
        if (!controller.signal.aborted) setError((e as Error).message);
      });
    return () => controller.abort();
  }, [revision, refresh, coordinated]);
  async function mutate(path: string, body: unknown, message: string) {
    setBusy(true);
    setError('');
    setNotice('');
    try {
      await api(path, body, csrf);
      setNotice(message);
      setRefresh((n) => n + 1);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function inspect(id: string) {
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    setBusy(true);
    setError('');
    setPreview(null);
    onSelect(null);
    try {
      const value = await api<Preview>(
        '/admin/cluster/models/catalog/preview',
        { revision, settings, id },
        csrf,
        { signal: controller.signal },
      );
      if (!controller.signal.aborted) setPreview({ key, value });
    } catch (e) {
      if (!controller.signal.aborted) setError((e as Error).message);
    } finally {
      if (request.current === controller) setBusy(false);
    }
  }
  return (
    <section className="management-card">
      <h2>Retained model sets</h2>
      <p>
        Keep an explicit copy of the installed model files before replacing or
        disabling them. Selecting a retained set preserves this draft’s rules,
        thresholds and current provider credentials. Its shadow candidate is
        included in the preview.
      </p>
      <p className="small muted">
        Removing a retained copy does not delete installed models or a staged
        rollout. Retained copies live on the coordinator and must be included in
        its backups.
      </p>
      {!coordinated && (
        <p className="notice">
          Enable coordinated changes before retaining or selecting models.
        </p>
      )}
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {notice && <output>{notice}</output>}
      <label>
        Retained set name
        <input
          value={label}
          maxLength={80}
          onChange={(e) => setLabel(e.target.value)}
          disabled={disabled || busy || !coordinated}
        />
      </label>
      <Button
        variant="outline"
        disabled={disabled || busy || !coordinated || !label.trim()}
        onClick={() =>
          void mutate(
            '/admin/cluster/models/catalog',
            { revision, label: label.trim() },
            'Installed model files retained. The active policy is unchanged.',
          )
        }
      >
        Retain installed models
      </Button>
      {coordinated && !items && !error && <p>Loading retained sets…</p>}
      {coordinated && (
        <Button
          variant="outline"
          disabled={disabled || busy}
          onClick={() => setRefresh((n) => n + 1)}
        >
          Refresh retained sets
        </Button>
      )}
      {items && (
        <>
          <p className="small muted">
            {items.entries.length} / {items.max_sets} sets · maximum{' '}
            {(items.max_bytes / 1024 ** 3).toLocaleString('en-GB')} GiB of
            retained model files
          </p>
          <CatalogTable
            entries={items.entries}
            disabled={disabled || busy}
            onPreview={(id) => void inspect(id)}
            onRemove={(id) => {
              request.current?.abort();
              setPreview(null);
              if (selected === id) onSelect(null);
              void mutate(
                '/admin/cluster/models/catalog/remove',
                { id },
                'Retained copy removed. Installed models and staged rollouts are unchanged.',
              );
            }}
          />
        </>
      )}
      {current && (
        <>
          <ModelManifest value={current} sourceLabel="Selected retained set" />
          <CatalogQualification value={current.qualification} />
          <p>
            Shadow candidate:{' '}
            {current.installation['/quality/candidate'] ? (
              <code>{current.installation['/quality/candidate'].sha256}</code>
            ) : (
              'Disabled in this selection'
            )}
          </p>
          <Button
            disabled={disabled || busy}
            onClick={() =>
              onSelect({
                id: current.id,
                digest: current.installation_sha256,
                quality_candidate: current.quality_candidate,
              })
            }
          >
            Use this retained set in the next save
          </Button>
        </>
      )}
      {selected && (
        <p className="notice">
          Retained model selection is a draft. Save settings to prepare it on
          every MX.{' '}
          <Button
            variant="outline"
            disabled={disabled || busy}
            onClick={() => onSelect(null)}
          >
            Clear model selection
          </Button>
        </p>
      )}
    </section>
  );
}
