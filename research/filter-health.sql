-- Read-only operational aggregates. No subjects, addresses, URLs or bodies.
-- Run on the coordinator: psql -X -v ON_ERROR_STOP=1 -d noisefence -f filter-health.sql
-- This is coverage/disagreement monitoring, NOT accuracy measurement.
BEGIN READ ONLY;
SET LOCAL statement_timeout='30s';
SET LOCAL timezone='UTC';
SELECT date(to_timestamp(created)) AS day_utc, count(*) AS messages,
 count(*) FILTER (WHERE score IS NULL) AS score_unavailable,
 count(*) FILTER (WHERE category='spam') AS spam,
 count(*) FILTER (WHERE category='publicity') AS pub,
 count(*) FILTER (WHERE scan#>>'{recipient_decision,classification}'='unassessed') AS unassessed,
 count(*) FILTER (WHERE scan#>>'{llm,status}'='complete') AS llm_complete
FROM noisefence.messages WHERE NOT is_dsn AND created>=extract(epoch from now()-interval '7 days')
GROUP BY 1 ORDER BY 1;
SELECT p AS provider, scan#>>ARRAY['protection',p,'status'] AS status,
 scan#>>ARRAY['protection',p,'failure'] AS failure, count(*) AS messages,
 sum(coalesce((scan#>>ARRAY['protection',p,'omitted'])::bigint,0)) AS omitted_indicators
FROM noisefence.messages CROSS JOIN (VALUES('crdf'),('virustotal')) providers(p)
WHERE NOT is_dsn AND created>=extract(epoch from now()-interval '7 days') GROUP BY 1,2,3 ORDER BY 1,2,3;
SELECT category AS noisefence_category,scan#>>'{rspamd,status}' AS rspamd_status,
 scan#>>'{rspamd,action}' AS rspamd_action, count(*) AS messages
FROM noisefence.messages WHERE NOT is_dsn AND created>=extract(epoch from now()-interval '7 days')
GROUP BY 1,2,3 ORDER BY 1,2,3;
SELECT scan#>>'{mailing,status}' AS status,scan#>>'{mailing,verdict}' AS kind,
 category AS decision,count(*) AS messages
FROM noisefence.messages WHERE NOT is_dsn AND created>=extract(epoch from now()-interval '7 days')
GROUP BY 1,2,3 ORDER BY 1,2,3;
COMMIT;
