WITH jobs AS (
 SELECT COUNT(*)::bigint AS rows,
  bool_or(COALESCE(m.scan#>>'{{rspamd,status}}'='complete',false)) AS completed,
  bool_or(COALESCE(m.scan#>>'{{rspamd,status}}'='complete' AND m.scan#>>'{{rspamd,comparison}}'='agreement',false)) AS agreement,
  bool_or(COALESCE(m.scan#>>'{{rspamd,status}}'='complete' AND m.scan#>>'{{rspamd,comparison}}'='disagreement',false)) AS disagreement,
  bool_or(COALESCE(m.scan#>>'{{rspamd,status}}'='complete' AND m.scan#>>'{{rspamd,comparison}}'='inconclusive',false)) AS inconclusive,
  bool_or(COALESCE(m.scan#>>'{{rspamd,status}}'='pending' AND (m.scan#>>'{{rspamd,expires_at}}')::bigint>=EXTRACT(EPOCH FROM CURRENT_TIMESTAMP)::bigint,false)) AS pending
 FROM noisefence.messages m JOIN noisefence.message_versions v ON v.id=m.id WHERE {scope}
 GROUP BY COALESCE('job:'||NULLIF(m.scan#>>'{{rspamd,job_id}}',''),
                   'transaction:'||NULLIF(m.scan->>'transaction_id',''), 'row:'||m.id)
)
SELECT COUNT(*)::bigint, COUNT(*) FILTER(WHERE completed)::bigint,
 COUNT(*) FILTER(WHERE completed AND agreement AND NOT disagreement AND NOT inconclusive)::bigint,
 COUNT(*) FILTER(WHERE completed AND disagreement AND NOT agreement AND NOT inconclusive)::bigint,
 COUNT(*) FILTER(WHERE completed AND (inconclusive OR agreement::integer+disagreement::integer!=1))::bigint,
 COUNT(*) FILTER(WHERE pending AND NOT completed)::bigint, COALESCE(SUM(rows),0)::bigint
FROM jobs
