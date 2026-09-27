'use client';
import { useEffect, useState } from 'react';
import { api } from './client';
import { ReleaseReadinessView, type Readiness } from './release-readiness-view';

export function ReleaseReadiness({ revision }: { revision: number }) {
  const [loaded, setLoaded] = useState<{
    revision: number;
    report: Readiness;
  } | null>(null);
  const [failure, setFailure] = useState<{
    revision: number;
    message: string;
  } | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    api<Readiness>('/quality/release-readiness', undefined, undefined, {
      signal: controller.signal,
    })
      .then((report) => {
        if (!controller.signal.aborted) {
          setLoaded({ revision, report });
          setFailure(null);
        }
      })
      .catch((e) => {
        if (!controller.signal.aborted)
          setFailure({ revision, message: e.message });
      });
    return () => controller.abort();
  }, [revision]);
  return (
    <ReleaseReadinessView
      report={loaded?.revision === revision ? loaded.report : null}
      error={failure?.revision === revision ? failure.message : ''}
    />
  );
}
