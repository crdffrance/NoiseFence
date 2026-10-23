import { adaptiveClasses, adaptiveLabels, adaptiveStatus, type AdaptiveReport } from './adaptive-types';

export function AdaptiveOpinions({report}:{report?:AdaptiveReport|null}) {
  return <details><summary>Bayes and neural opinions</summary>
    <p>{report ? adaptiveStatus(report.status) : "No multiclass observation recorded for this message."}{report?.model && ` · ${report.model}`}</p>
    {report?.category && <p>Opinion: <strong>{adaptiveLabels[report.category]}</strong>{report.proposed_action && ` · simulated action: ${{observe:'observation',tag:'tagging',quarantine:"quarantine"}[report.proposed_action]}`}</p>}
    {report?.bayes_strengths?.length === 5 && report.neural_strengths?.length === 5 && <div className="overflow-x-auto">
      <table className="adaptive-scores"><caption>Uncalibrated relative strengths; these are not threat probabilities.</caption>
        <thead><tr><th>Category</th><th>Bayes</th><th>Neural</th></tr></thead>
        <tbody>{adaptiveClasses.map((c,i)=><tr key={c}><th>{adaptiveLabels[c]}</th><td>{report.bayes_strengths![i].toFixed(3)}</td><td>{report.neural_strengths![i].toFixed(3)}</td></tr>)}</tbody>
      </table>
    </div>}
    </details>;
}
