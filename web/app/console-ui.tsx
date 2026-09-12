'use client';
import { useEffect, useId, useRef, type ReactNode } from 'react';
import { X } from 'lucide-react';
import { Button } from '@/components/ui/button';

export function SectionTabs<T extends string>({
  id,
  label,
  items,
  value,
  onChange,
  presentation = 'line',
}: {
  id: string;
  label: string;
  items: readonly {
    id: T;
    label: string;
    description?: string;
    icon?: ReactNode;
  }[];
  value: T;
  onChange: (value: T) => void;
  presentation?: 'line' | 'cards';
}) {
  return (
    <div
      className={`section-tabs ${presentation === 'cards' ? 'section-tabs-cards' : ''}`}
      role="tablist"
      aria-label={label}
    >
      {items.map((item, index) => (
        <button
          key={item.id}
          type="button"
          role="tab"
          id={`${id}-tab-${item.id}`}
          aria-controls={`${id}-panel-${item.id}`}
          aria-selected={value === item.id}
          tabIndex={value === item.id ? 0 : -1}
          onClick={() => onChange(item.id)}
          onKeyDown={(event) => {
            const next =
              event.key === 'ArrowRight'
                ? (index + 1) % items.length
                : event.key === 'ArrowLeft'
                  ? (index + items.length - 1) % items.length
                  : event.key === 'Home'
                    ? 0
                    : event.key === 'End'
                      ? items.length - 1
                      : -1;
            if (next < 0) return;
            event.preventDefault();
            onChange(items[next].id);
            document.getElementById(`${id}-tab-${items[next].id}`)?.focus();
          }}
        >
          {presentation === 'cards' ? (
            <>
              <span className="section-tab-icon" aria-hidden="true">
                {item.icon}
              </span>
              <span className="section-tab-copy">
                <strong>{item.label}</strong>
                <small>{item.description}</small>
              </span>
            </>
          ) : (
            item.label
          )}
        </button>
      ))}
    </div>
  );
}

export function ConfirmDialog({
  title,
  children,
  confirmLabel,
  danger = false,
  busy,
  onCancel,
  onConfirm,
}: {
  title: string;
  children: ReactNode;
  confirmLabel: string;
  danger?: boolean;
  busy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const cancel = useRef<HTMLButtonElement>(null);
  const heading = useId();
  const description = useId();
  useEffect(() => {
    const previous = document.activeElement;
    const dialog = ref.current;
    dialog?.showModal();
    cancel.current?.focus();
    return () => {
      dialog?.close();
      if (previous instanceof HTMLElement && previous.isConnected)
        previous.focus();
    };
  }, []);
  return (
    <dialog
      ref={ref}
      className="confirm-dialog"
      aria-labelledby={heading}
      aria-describedby={description}
      onCancel={(event) => {
        event.preventDefault();
        if (!busy) onCancel();
      }}
    >
      <div className="dialog-heading">
        <h2 id={heading}>{title}</h2>
        <Button
          variant="ghost"
          aria-label="Fermer la confirmation"
          disabled={busy}
          onClick={onCancel}
        >
          <X size={18} />
        </Button>
      </div>
      <div id={description} className="dialog-description">
        {children}
      </div>
      <div className="dialog-actions">
        <button
          ref={cancel}
          type="button"
          className="cancel-action"
          disabled={busy}
          onClick={onCancel}
        >
          Annuler
        </button>
        <Button
          variant={danger ? 'destructive' : 'default'}
          disabled={busy}
          onClick={onConfirm}
        >
          {busy ? 'Traitement…' : confirmLabel}
        </Button>
      </div>
    </dialog>
  );
}
