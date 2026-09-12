-- Shared predicate for rows and exact totals, in one read snapshot.
(m.created>=?4 OR m.raw_present=1 OR EXISTS(SELECT 1 FROM cluster_origin o WHERE o.message_id=m.id AND o.raw_present=1)) AND EXISTS(SELECT 1 FROM deliveries d JOIN console_access g ON g.delivery_id=d.id WHERE d.message_id=m.id AND g.username=?1
 AND (?6='' OR lower(substr(d.address,-length(?6)-1))='@'||lower(?6) OR lower(substr(d.destination,-length(?6)-1))='@'||lower(?6))) AND ({search})
 AND (?2='all'
 OR (?2='spam' AND COALESCE(json_extract(m.scan,'$.delivery_classification')='spam',json_extract(m.scan,'$.decision.outcome')='unwanted',json_extract(m.scan,'$.complete')=1 AND json_extract(m.scan,'$.score')>=?5))
 OR (?2='review' AND json_extract(m.scan,'$.complete')=1 AND COALESCE(json_extract(m.scan,'$.delivery_classification')='undetermined',json_extract(m.scan,'$.decision.outcome')='undetermined'))
 OR (?2='incomplete' AND json_extract(m.scan,'$.complete')=0)
 OR (?2='quarantined' AND EXISTS(SELECT 1 FROM deliveries qd JOIN console_access qg ON qg.delivery_id=qd.id WHERE qd.message_id=m.id AND qg.username=?1 AND qd.status='quarantined'
 AND (?6='' OR lower(substr(qd.address,-length(?6)-1))='@'||lower(?6) OR lower(substr(qd.destination,-length(?6)-1))='@'||lower(?6))))
 OR (?2='pending' AND EXISTS(SELECT 1 FROM deliveries pd JOIN console_access pg ON pg.delivery_id=pd.id WHERE pd.message_id=m.id AND pg.username=?1 AND pd.status IN ('pending','sending')
 AND (?6='' OR lower(substr(pd.address,-length(?6)-1))='@'||lower(?6) OR lower(substr(pd.destination,-length(?6)-1))='@'||lower(?6))))
 OR (?2='legitimate' AND COALESCE(json_extract(m.scan,'$.delivery_classification') IN ('legitimate','publicity'),json_extract(m.scan,'$.decision.outcome')='legitimate',json_extract(m.scan,'$.complete')=1 AND json_extract(m.scan,'$.score')<?5) AND NOT {publicity})
 OR (?2='publicity' AND COALESCE(json_extract(m.scan,'$.delivery_classification') IN ('legitimate','publicity'),json_extract(m.scan,'$.decision.outcome')='legitimate',json_extract(m.scan,'$.complete')=1 AND json_extract(m.scan,'$.score')<?5) AND {publicity})
 OR (?2='publicity_signal' AND {signal}))
