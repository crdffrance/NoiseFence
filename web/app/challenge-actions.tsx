'use client';
import { useEffect, useRef, useState } from 'react';
import { Button } from '@/components/ui/button';
import { api } from './client';
import { ConfirmDialog } from './console-ui';

export default function ChallengeActions({
  messageId,
  recipient,
  csrf,
  disabled,
}: {
  messageId: string;
  recipient: string;
  csrf: string;
  disabled: boolean;
}) {
  const [mailbox, setMailbox] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const active = useRef<AbortController | null>(null);
  useEffect(
    () => () => {
      active.current?.abort();
    },
    [],
  );
  async function perform(action: 'prepare' | 'send' | 'revoke') {
    if (busy) return;
    active.current?.abort();
    const controller = new AbortController();
    active.current = controller;
    setBusy(true);
    setError('');
    setNotice('');
    try {
      const result = await api<{
        mailbox?: string;
        expires_at?: number;
        revoked?: boolean;
      }>(
        `/messages/${encodeURIComponent(messageId)}/challenge${action === 'send' ? '' : `/${action}`}`,
        { recipient },
        csrf,
        { signal: controller.signal },
      );
      if (controller.signal.aborted) return;
      if (action === 'prepare') {
        if (!result.mailbox)
          throw new Error('Auteur authentifié non disponible.');
        setMailbox(result.mailbox);
      } else {
        setMailbox(null);
        setNotice(
          action === 'send'
            ? 'Demande mise en file. La confirmation permettra de libérer uniquement cette livraison.'
            : result.revoked
              ? 'Lien de confirmation révoqué.'
              : 'Aucun lien actif à révoquer.',
        );
      }
    } catch (exception) {
      if (!controller.signal.aborted) setError((exception as Error).message);
    } finally {
      if (!controller.signal.aborted) setBusy(false);
    }
  }
  return (
    <div>
      <div className="feedback-actions">
        <Button
          variant="outline"
          disabled={disabled || busy}
          onClick={() => void perform('prepare')}
        >
          Demander une confirmation à l’auteur
        </Button>
        <Button
          variant="ghost"
          disabled={disabled || busy}
          onClick={() => void perform('revoke')}
        >
          Révoquer le lien
        </Button>
      </div>
      {notice && <output className="small muted">{notice}</output>}
      {error && !mailbox && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {mailbox && (
        <ConfirmDialog
          title="Envoyer une demande de confirmation ?"
          confirmLabel="Envoyer la demande"
          busy={busy}
          onCancel={() => {
            setMailbox(null);
            setError('');
          }}
          onConfirm={() => void perform('send')}
        >
          <p>
            Un message sera envoyé à <strong>{mailbox}</strong>, l’auteur
            authentifié de cet e-mail.
          </p>
          <p>
            Son lien à usage unique pourra libérer la copie destinée à{' '}
            <strong>{recipient}</strong>. Il ne créera pas d’exception pour les
            prochains messages.
          </p>
          {error && (
            <p role="alert" className="error">
              {error}
            </p>
          )}
        </ConfirmDialog>
      )}
    </div>
  );
}
