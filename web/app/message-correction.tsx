import { useEffect, useRef, useState } from 'react';
import { Button } from '@/components/ui/button';
import { api } from './client';
import { adaptiveLabels, type AdaptiveReport } from './adaptive-types';
import { AdaptiveOpinions } from './adaptive';
import { CorrectionForm } from './correction-form';
import {
  correctionLabels,
  correctionRequest,
  type CorrectionDraft,
  type DomainLabel,
} from './correction';
import type { FeedbackCategory } from './mailing';

export function MessageCorrection({
  id,
  csrf,
  saved,
  report,
  blocked,
  onBusy,
  onDirty,
  onSaved,
  focusAfterSave = false,
}: {
  focusAfterSave?: boolean;
  id: string;
  csrf: string;
  saved: FeedbackCategory | null;
  report?: AdaptiveReport | null;
  blocked: boolean;
  onBusy: (value: boolean) => void;
  onDirty: (value: boolean) => void;
  onSaved: (category: FeedbackCategory | undefined, notice: string) => void;
}) {
  const initial: CorrectionDraft = {
    mode: 'general',
    category: saved ?? '',
    domain: '',
    threat: 'spam',
  };
  const [draft, setDraft] = useState<CorrectionDraft>(initial);
  const [error, setError] = useState(''),
    [busy, setBusy] = useState(false),
    [revision, setRevision] = useState(0);
  const [loaded, setLoaded] = useState<{
    id: string;
    revision: number;
    domains: DomainLabel[] | null;
    error: string;
  } | null>(null);
  const current =
    loaded?.id === id && loaded.revision === revision ? loaded : null;
  const domains = current?.domains ?? null,
    loadError = current?.error ?? '';
  const mounted = useRef(true),
    writing = useRef(false);
  const dirty =
    draft.category !== initial.category ||
    draft.mode !== 'general' ||
    draft.domain !== '' ||
    draft.threat !== 'spam';
  useEffect(() => {
    onDirty(dirty);
    return () => onDirty(false);
  }, [dirty, onDirty]);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      if (writing.current) onBusy(false);
    };
  }, [onBusy]);
  useEffect(() => {
    const controller = new AbortController();
    api<{ domains: DomainLabel[] }>(
      `/messages/${encodeURIComponent(id)}/adaptive-label`,
      undefined,
      undefined,
      { signal: controller.signal },
    )
      .then((data) => {
        if (!controller.signal.aborted)
          setLoaded({ id, revision, domains: data.domains, error: '' });
      })
      .catch(() => {
        if (!controller.signal.aborted)
          setLoaded({
            id,
            revision,
            domains: null,
            error:
              'Domain labels could not be loaded. General corrections remain available; they replace any previous detailed labels.',
          });
      });
    return () => controller.abort();
  }, [id, revision]);
  useEffect(() => {
    if (!dirty && !busy) return;
    const warn = (event: BeforeUnloadEvent) => {
      event.preventDefault();
    };
    window.addEventListener('beforeunload', warn);
    return () => window.removeEventListener('beforeunload', warn);
  }, [dirty, busy]);
  const choices = domains?.filter((d) => draft.mode !== 'withdraw' || d.class);
  const domain =
    draft.domain || (choices?.length === 1 ? choices[0].domain : '');
  const request = correctionRequest({ ...draft, domain }, domains);
  const refinements = domains?.filter((d) => d.class) ?? [];
  async function save() {
    if (!request || busy || blocked || writing.current) return;
    writing.current = true;
    setBusy(true);
    onBusy(true);
    setError('');
    try {
      await api(
        `/messages/${encodeURIComponent(id)}/${request.endpoint}`,
        request.body,
        csrf,
      );
      if (mounted.current) onSaved(request.category, request.notice);
    } catch (e) {
      if (mounted.current)
        setError(
          e instanceof Error
            ? e.message
            : 'Correction could not be saved. Your draft is retained.',
        );
    } finally {
      writing.current = false;
      if (mounted.current) {
        setBusy(false);
        onBusy(false);
      }
    }
  }
  function change(values: Partial<CorrectionDraft>) {
    setDraft((previous) => ({ ...previous, ...values }));
    setError('');
  }
  return (
    <section className="message-correction" aria-label="Correct this message">
      <CorrectionForm
        focusOnMount={focusAfterSave}
        scope="operational"
        title="Correct classification"
        saved={
          saved
            ? correctionLabels[saved]
            : 'No correction recorded for your account'
        }
        onSave={() => void save()}
        onReset={
          dirty
            ? () => {
                setDraft(initial);
                setError('');
              }
            : undefined
        }
        busy={busy}
        disabled={blocked || !request}
        submitLabel={
          draft.mode === 'withdraw'
            ? 'Withdraw detailed label'
            : 'Save correction'
        }
        error={error}
      >
        <label>
          Correction detail
          <select
            value={draft.mode}
            disabled={blocked}
            onChange={(e) =>
              change({
                mode: e.target.value as CorrectionDraft['mode'],
                domain: '',
              })
            }
          >
            <option value="general">General correction</option>
            <option value="detail">Add a domain learning label</option>
            <option value="withdraw">Withdraw a domain learning label</option>
          </select>
        </label>
        {draft.mode !== 'withdraw' && (
          <label>
            Your classification
            <select
              value={draft.category}
              disabled={blocked}
              onChange={(e) =>
                change({
                  category: e.target.value as CorrectionDraft['category'],
                })
              }
            >
              <option value="">Choose after checking the message</option>
              {Object.entries(correctionLabels).map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </label>
        )}
        {draft.mode !== 'general' && (
          <label>
            Learning domain
            <select
              value={domain}
              disabled={blocked || !domains}
              onChange={(e) => change({ domain: e.target.value })}
            >
              <option value="">Choose an authorized domain</option>
              {choices?.map((d) => (
                <option key={d.domain} value={d.domain}>
                  {d.domain}
                  {d.class ? ` · saved: ${adaptiveLabels[d.class]}` : ''}
                </option>
              ))}
            </select>
          </label>
        )}
        {draft.mode === 'detail' && draft.category === 'spam' && (
          <label>
            Verified unwanted category
            <select
              value={draft.threat}
              disabled={blocked}
              onChange={(e) =>
                change({ threat: e.target.value as CorrectionDraft['threat'] })
              }
            >
              <option value="spam">Spam · unspecified</option>
              <option value="phishing">Phishing · credential theft</option>
              <option value="scam">Scam · other fraud</option>
            </select>
          </label>
        )}
        <p className="muted small correction-wide">
          {draft.mode === 'withdraw'
            ? 'Only the selected detailed label is removed. Your general correction stays recorded.'
            : draft.mode === 'detail'
              ? 'Saving updates your general correction and records the chosen domain label in one transaction. Other detailed labels for this message are replaced.'
              : 'Saving updates your general correction and removes any previous detailed learning labels for this message.'}
        </p>
        {draft.mode !== 'withdraw' && (
          <p className="muted small correction-wide">
            Pub means wanted marketing. Use Spam for unwanted offers. If unsure,
            leave the message unlabelled. Feedback does not release quarantine.
          </p>
        )}
      </CorrectionForm>
      <div className="correction-labels">
        {!domains && !loadError && (
          <output>Loading saved domain labels…</output>
        )}
        {loadError && (
          <>
            <output className="muted small">{loadError}</output>
            <Button
              type="button"
              variant="outline"
              disabled={busy || blocked}
              onClick={() => setRevision((r) => r + 1)}
            >
              Retry labels
            </Button>
          </>
        )}
        {domains && (
          <p className="muted small">
            {refinements.length
              ? `Saved detailed labels: ${refinements.map((d) => `${d.domain} — ${adaptiveLabels[d.class!]}`).join('; ')}.`
              : 'No detailed learning labels saved.'}
          </p>
        )}
      </div>
      <AdaptiveOpinions report={report} />
    </section>
  );
}
