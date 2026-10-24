import { useEffect, useId, useRef, type ReactNode } from 'react';
import { Button } from '@/components/ui/button';
import { correctionScopes, type CorrectionScope } from './correction';

export function CorrectionForm({
  scope,
  title,
  saved,
  children,
  onSave,
  onReset,
  disabled,
  busy,
  error,
  submitLabel,
  compact = false,
  focusOnMount = false,
}: {
  scope: CorrectionScope;
  title: string;
  saved?: string;
  children: ReactNode;
  onSave: () => void;
  onReset?: () => void;
  disabled: boolean;
  busy: boolean;
  error?: string;
  submitLabel?: string;
  compact?: boolean;
  focusOnMount?: boolean;
}) {
  const id = useId(),
    purpose = correctionScopes[scope],
    heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => {
    if (focusOnMount) heading.current?.focus();
  }, [focusOnMount]);
  return (
    <form
      className="correction-form"
      aria-labelledby={`${id}-title`}
      aria-describedby={`${id}-scope`}
      onSubmit={(event) => {
        event.preventDefault();
        if (!disabled && !busy) onSave();
      }}
    >
      <div className="correction-heading">
        <h3 ref={heading} tabIndex={-1} id={`${id}-title`}>
          {title}
        </h3>
        <span className="correction-scope">{purpose.label}</span>
      </div>
      <p id={`${id}-scope`} className="muted small">
        {compact
          ? purpose.label + ' · delivered messages remain unchanged.'
          : purpose.detail}
      </p>
      {saved && (
        <p className="correction-saved">
          <strong>Saved:</strong> {saved}
        </p>
      )}
      <fieldset disabled={busy} className="correction-fields">
        <legend className="sr-only">Your verified classification</legend>
        {children}
      </fieldset>
      <div className="feedback-actions">
        <Button type="submit" disabled={disabled || busy}>
          {busy ? 'Saving…' : (submitLabel ?? 'Save annotation')}
        </Button>
        {onReset && (
          <Button
            type="button"
            variant="outline"
            disabled={busy}
            onClick={onReset}
          >
            Reset changes
          </Button>
        )}
      </div>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
    </form>
  );
}
