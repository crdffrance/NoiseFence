import { actionBasis, coverageRequirements, type ActionCoverage } from './action-coverage';

export function ActionCoverageDetails({ coverage }: { coverage?: ActionCoverage | null }) {
  if (!coverage) return null;
  return <details className="diagnostic-disclosure">
    <summary>Action requirements · {actionBasis(coverage.basis)}</summary>
    <p className="diagnostic-muted">{coverage.partial_actions ? 'Decision-specific partial-action policy' : 'Complete-analysis policy'} · {coverage.version}. These are receipt-time requirements; observation mode and Proton validation still constrain delivery.</p>
    {coverage.required.length > 0 || coverage.missing.length > 0
      ? <ul>{coverageRequirements(coverage).map(r => <li key={r.id}><strong>{r.met ? 'Met' : 'Missing'}</strong> · {r.label}</li>)}</ul>
      : <p className="diagnostic-muted">Delivery without a tag requires no threat finding.</p>}
  </details>;
}
