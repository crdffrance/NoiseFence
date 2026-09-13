'use client';
import { useState } from 'react';
import { SlidersHorizontal, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  emptySearch,
  searchFilterCount,
  searchParameters,
  type SearchFilters,
} from './message-search';

export function MessageSearchControls({
  value,
  onChange,
}: {
  value: SearchFilters;
  onChange: (filters: SearchFilters) => void;
}) {
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState(value);
  const [error, setError] = useState('');
  const [previousValue, setPreviousValue] = useState(value);
  if (value !== previousValue) {
    setPreviousValue(value);
    setDraft(value);
    setError('');
  }
  const count = searchFilterCount(value);
  return (
    <div className="advanced-mail-search">
      <div className="search-help-row">
        <p>
          Subjects, addresses, rules and IDs · All words must match. Use &quot;&nbsp;<code>&quot;exact phrase&quot;</code>
          &nbsp;&quot; for an exact phrase.
        </p>
        <Button
          variant={count ? 'secondary' : 'ghost'}
          aria-expanded={open}
          aria-controls="mail-search-fields"
          onClick={() => setOpen(!open)}
        >
          <SlidersHorizontal size={15} /> Advanced Search
          {count ? ` (${count})` : ''}
        </Button>
      </div>
      {open && (
        <form
          id="mail-search-fields"
          className="search-fields-panel"
          onSubmit={(event) => {
            event.preventDefault();
            try {
              searchParameters('', 'all', '', 0, draft);
              setError('');
              onChange({ ...draft });
            } catch (e) {
              setError((e as Error).message);
            }
          }}
        >
          <div className="search-fields-grid">
            {(
              [
                ['node', "MX server", "mx2 or local"],
                ['sender', "Sender", "address or domain"],
                ['recipient', "Recipient", "address or alias authorized"],
                ['subject', "Subject", "words or \"exact expression\""],
                ['rule', "Rule triggered", "Rule ID"],
                ['id', "NoiseFence ID", "identifier or fragment"],
              ] as const
            ).map(([field, label, placeholder]) => (
              <label key={field}>
                {label}
                <Input
                  value={draft[field]}
                  maxLength={256}
                  placeholder={placeholder}
                  onChange={(e) =>
                    setDraft({ ...draft, [field]: e.target.value })
                  }
                />
              </label>
            ))}
            <label>
              Delivery
              <select
                value={draft.status}
                onChange={(e) => setDraft({ ...draft, status: e.target.value })}
              >
                <option value="">All states</option>
                <option value="pending">Pending</option>
                <option value="sending">In progress</option>
                <option value="delivered">Delivered</option>
                <option value="failed">Failed</option>
                <option value="notified">Processed failure</option>
                <option value="dsn_suppressed">Blocked (anti-backscatter)</option>
                <option value="quarantined">Quarantine</option>
                <option value="discarded">Deleted</option>
              </select>
            </label>
            <label htmlFor="search-after">
              Received from
              <Input
                type="date"
                id="search-after"
                value={draft.after}
                onChange={(e) => setDraft({ ...draft, after: e.target.value })}
              />
            </label>
            <label htmlFor="search-before">
              Received until (included)
              <Input
                type="date"
                id="search-before"
                value={draft.before}
                onChange={(e) => setDraft({ ...draft, before: e.target.value })}
              />
            </label>
            <label htmlFor="search-min_score">
              Score minimum / 100
              <Input
                type="number"
                min={0}
                max={100}
                step="any"
                placeholder="0"
                id="search-min_score"
                value={draft.min_score}
                onChange={(e) =>
                  setDraft({ ...draft, min_score: e.target.value })
                }
              />
            </label>
            <label htmlFor="search-max_score">
              Score maximum / 100
              <Input
                type="number"
                min={0}
                max={100}
                step="any"
                placeholder="100"
                id="search-max_score"
                value={draft.max_score}
                onChange={(e) =>
                  setDraft({ ...draft, max_score: e.target.value })
                }
              />
            </label>
          </div>
          <p className="search-retention">
            Search retained metadata from the last 30 days and unresolved messages. Bodies and attachments are not indexed. Dates use your time zone; score filters match the displayed index, including partial results.
          </p>
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
          <div className="search-field-actions">
            <Button type="submit">Apply criteria</Button>
            <Button
              type="button"
              variant="ghost"
              onClick={() => {
                setDraft(emptySearch);
                onChange(emptySearch);
                setError('');
              }}
            >
              <X size={14} /> Clear criteria
            </Button>
          </div>
        </form>
      )}
    </div>
  );
}
