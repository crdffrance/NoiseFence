import type { ReactNode } from 'react';
import { SectionTabs } from './console-ui';
import type { ResearchTab } from './quality-link';

const tabs = [
  { id: 'samples', label: 'Samples & evaluation' },
  { id: 'comparison', label: 'Engine comparison' },
  { id: 'reliability', label: 'Rule reliability' },
] as const;

export function QualityNavigation({
  tab,
  onChange,
  children,
}: {
  tab: ResearchTab | null;
  onChange: (tab: ResearchTab) => void;
  children: ReactNode;
}) {
  if (!tab) return <>{children}</>;
  return (
    <div className="quality-research">
      <div className="page-heading">
        <div>
          <p className="eyebrow">MEASURE & IMPROVE</p>
          <h1>Quality & research</h1>
          <p className="page-intro">
            Evaluate labelled samples, compare independent opinions and
            investigate errors in your accessible messages.
          </p>
        </div>
      </div>
      <SectionTabs
        id="quality-research"
        label="Quality & research"
        items={tabs}
        value={tab}
        onChange={onChange}
      />
      <div
        role="tabpanel"
        id={`quality-research-panel-${tab}`}
        aria-labelledby={`quality-research-tab-${tab}`}
        tabIndex={0}
      >
        {children}
      </div>
    </div>
  );
}
