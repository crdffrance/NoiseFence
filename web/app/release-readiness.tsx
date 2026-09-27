'use client';
import { useEffect, useState } from 'react';
import { api } from './client';
type Cohort = {
  messages: number;
  usable: number;
  wanted: number;
  unwanted: number;
  uncertain: number;
  unlabelled: number;
};
type Readiness = {
  schema: string;
  current_cohort: string;
  cohorts: Record<string, Cohort>;
  minimum_wanted_test_messages: number;
  minimum_unwanted_test_messages: number;
  qualification_required: boolean;
  blockers: string[];
};
export function ReleaseReadiness({ revision }: { revision: number }) {
  const [report, setReport] = useState<Readiness | null>(null),
    [error, setError] = useState('');
  useEffect(() => {
    const controller = new AbortController();
    api<Readiness>('/quality/release-readiness', undefined, undefined, {
      signal: controller.signal,
    })
      .then((r) => {
        if (!controller.signal.aborted) {
          setReport(r);
          setError('');
        }
      })
      .catch((e) => {
        if (!controller.signal.aborted) setError(e.message);
      });
    return () => controller.abort();
  }, [revision]);
  const current = report?.cohorts[report.current_cohort];
  return (
    <section className="panel">
      <p className="eyebrow">RELEASE QUALIFICATION</p>
      <h2>Evidence before activation</h2>
      <p>
        A populated dashboard or a high score does not establish detection
        quality. Training, calibration and independent evaluation use separate
        campaigns.
      </p>
      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : !report ? (
        <p>Loading dataset readiness…</p>
      ) : (
        <>
          <div className="assessment-facts">
            <span className="status review">
              Independent qualification required
            </span>
            <span>
              Current detector cohort:{' '}
              {report.current_cohort.slice(0, 12) || 'Not available'}
            </span>
          </div>
          <table>
            <thead>
              <tr>
                <th>Current cohort · your accessible messages</th>
                <th>Count</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Recorded messages</td>
                <td>{current?.messages ?? 0}</td>
              </tr>
              <tr>
                <td>Usable SMTP observations</td>
                <td>{current?.usable ?? 0}</td>
              </tr>
              <tr>
                <td>Human-labelled wanted</td>
                <td>{current?.wanted ?? 0}</td>
              </tr>
              <tr>
                <td>Human-labelled unwanted</td>
                <td>{current?.unwanted ?? 0}</td>
              </tr>
              <tr>
                <td>Unlabelled / uncertain</td>
                <td>
                  {current?.unlabelled ?? 0} / {current?.uncertain ?? 0}
                </td>
              </tr>
            </tbody>
          </table>
          <p className="muted small">
            The promotion contract requires at least{' '}
            {report.minimum_wanted_test_messages.toLocaleString('en-GB')} wanted
            and {report.minimum_unwanted_test_messages.toLocaleString('en-GB')}{' '}
            unwanted test messages, confidence bounds, campaign independence,
            provenance and latency checks. The counts above include development
            data and are not qualification results. Other detector cohorts:{' '}
            {
              Object.keys(report.cohorts).filter(
                (k) => k !== report.current_cohort,
              ).length
            }
            .
          </p>
        </>
      )}
    </section>
  );
}
