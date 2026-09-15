-- Deduplicate only AFTER recipient authorization and search scope. One original
-- SMTP transaction may have several delivery variants sharing a comparison job.
WITH jobs AS (
 SELECT COUNT(*) AS rows,
  MAX(CASE WHEN json_extract(m.scan,'$.rspamd.status')='complete' THEN 1 ELSE 0 END) AS completed,
  MAX(CASE WHEN json_extract(m.scan,'$.rspamd.status')='complete' AND json_extract(m.scan,'$.rspamd.comparison')='agreement' THEN 1 ELSE 0 END) AS agreement,
  MAX(CASE WHEN json_extract(m.scan,'$.rspamd.status')='complete' AND json_extract(m.scan,'$.rspamd.comparison')='disagreement' THEN 1 ELSE 0 END) AS disagreement,
  MAX(CASE WHEN json_extract(m.scan,'$.rspamd.status')='complete' AND json_extract(m.scan,'$.rspamd.comparison')='inconclusive' THEN 1 ELSE 0 END) AS inconclusive,
  MAX(CASE WHEN json_extract(m.scan,'$.rspamd.status')='pending' AND json_extract(m.scan,'$.rspamd.expires_at')>=unixepoch() THEN 1 ELSE 0 END) AS pending
 FROM messages m WHERE {scope} AND ?3>=0
 GROUP BY COALESCE('job:'||NULLIF(json_extract(m.scan,'$.rspamd.job_id'),''),
                   'transaction:'||NULLIF(json_extract(m.scan,'$.transaction_id'),''), 'row:'||m.id)
)
SELECT COUNT(*), COALESCE(SUM(completed),0),
 COALESCE(SUM(completed=1 AND agreement=1 AND disagreement=0 AND inconclusive=0),0),
 COALESCE(SUM(completed=1 AND disagreement=1 AND agreement=0 AND inconclusive=0),0),
 COALESCE(SUM(completed=1 AND (inconclusive=1 OR agreement+disagreement!=1)),0),
 COALESCE(SUM(pending=1 AND completed=0),0), COALESCE(SUM(rows),0)
FROM jobs
