-- Additive schema: historical messages and the original spool format are retained.
CREATE TABLE IF NOT EXISTS console_revisions(
 id INTEGER PRIMARY KEY AUTOINCREMENT, created INTEGER NOT NULL,
 username TEXT NOT NULL, settings TEXT NOT NULL
);
CREATE VIEW IF NOT EXISTS console_access AS
 SELECT u.username, d.id AS delivery_id FROM users u JOIN deliveries d
 WHERE u.disabled=0 AND (u.admin=1 OR EXISTS(
  SELECT 1 FROM grants g WHERE g.username=u.username AND (
   g.address=d.destination OR
   (substr(g.address,1,2)='*@' AND (
    lower(substr(d.destination,1-length(g.address)))=lower(substr(g.address,2)) OR
    lower(substr(d.address,1-length(g.address)))=lower(substr(g.address,2))
   ))
  )
 ));
CREATE TABLE IF NOT EXISTS console_user_versions(
 username TEXT PRIMARY KEY REFERENCES users(username) ON DELETE CASCADE,
 version INTEGER NOT NULL
);
-- Keep the binary spam label for existing trainers and older binaries. Explicit
-- PUB / legitimate labels are separate; old non-spam votes do not invent a subtype.
CREATE TABLE IF NOT EXISTS feedback_categories(
 username TEXT NOT NULL, message_id TEXT NOT NULL,
 category TEXT NOT NULL CHECK(category IN ('spam','publicity','legitimate')),
 PRIMARY KEY(username,message_id),
 FOREIGN KEY(username,message_id) REFERENCES feedback(username,message_id) ON DELETE CASCADE
);
-- An older binary can still overwrite a binary vote after a rollback. Clear its
-- old subtype even when both writes happen in the same second.
CREATE TRIGGER IF NOT EXISTS feedback_category_invalidate
AFTER UPDATE OF spam,created ON feedback BEGIN
 DELETE FROM feedback_categories WHERE username=NEW.username AND message_id=NEW.message_id;
END;

-- Schema v2 prevents old binaries from deleting a quarantined spool on cleanup.
CREATE TABLE IF NOT EXISTS delivery_policy(
 delivery_id INTEGER PRIMARY KEY REFERENCES deliveries(id) ON DELETE CASCADE,
 action TEXT NOT NULL CHECK(action IN ('deliver','tag','quarantine')),
 held_until INTEGER,
 released_at INTEGER
);
CREATE INDEX IF NOT EXISTS quarantine_expiry ON delivery_policy(held_until);

-- Bounded, recipient-scoped SMTP transcripts. Additive to schema v2: older
-- binaries can deliver and clean up normally; no queue state semantics change.
CREATE TABLE IF NOT EXISTS delivery_attempts(
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 delivery_id INTEGER NOT NULL REFERENCES deliveries(id) ON DELETE CASCADE,
 attempt INTEGER NOT NULL,
 trace TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS delivery_attempt_history ON delivery_attempts(delivery_id,id DESC);

-- Independent risk/type annotations and immutable, score-blind evaluation draws.
CREATE TABLE IF NOT EXISTS quality_batches(
 id TEXT PRIMARY KEY, username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
 created INTEGER NOT NULL, since INTEGER NOT NULL, until INTEGER NOT NULL,
 domain TEXT NOT NULL, seed TEXT NOT NULL, population INTEGER NOT NULL, selected INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS quality_members(
 batch_id TEXT NOT NULL REFERENCES quality_batches(id) ON DELETE CASCADE,
 message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
 rank INTEGER NOT NULL, PRIMARY KEY(batch_id,message_id)
);
CREATE TABLE IF NOT EXISTS quality_labels(
 username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
 message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
 risk TEXT NOT NULL CHECK(risk IN ('legitimate','spam','uncertain')),
 kind TEXT CHECK(kind IN ('conversation','transactional','notification','newsletter','promotion','other')),
 created INTEGER NOT NULL, PRIMARY KEY(username,message_id)
);
CREATE TRIGGER IF NOT EXISTS quality_label_invalidate
AFTER UPDATE OF spam,created ON feedback BEGIN
 DELETE FROM quality_labels WHERE username=NEW.username AND message_id=NEW.message_id;
END;
CREATE INDEX IF NOT EXISTS message_sender_history ON messages(CASE WHEN json_valid(scan) THEN json_extract(scan,'$.sender_history.key') END,created);

CREATE TABLE IF NOT EXISTS delivery_filtering(
 delivery_id INTEGER PRIMARY KEY REFERENCES deliveries(id) ON DELETE CASCADE,
 assessment TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS console_invitations(
 id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE,
 username TEXT NOT NULL, admin INTEGER NOT NULL, addresses TEXT NOT NULL,
 creator TEXT NOT NULL REFERENCES users(username), creator_version INTEGER NOT NULL,
 created INTEGER NOT NULL, expires INTEGER NOT NULL, version INTEGER NOT NULL DEFAULT 1,
 revoked INTEGER, accepted INTEGER
);
CREATE INDEX IF NOT EXISTS invitation_expiry ON console_invitations(expires);

-- Optional local category learning. Existing binary feedback remains authoritative.
CREATE TABLE IF NOT EXISTS adaptive_labels(
 username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
 message_id TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
 domain TEXT NOT NULL,
 class TEXT NOT NULL CHECK(class IN ('legitimate','publicity','spam','phishing','scam')),
 created INTEGER NOT NULL,
 PRIMARY KEY(username,message_id,domain)
);
CREATE INDEX IF NOT EXISTS adaptive_labels_domain ON adaptive_labels(domain,created);
CREATE TRIGGER IF NOT EXISTS adaptive_label_invalidate AFTER UPDATE OF spam,created ON feedback BEGIN
 DELETE FROM adaptive_labels WHERE username=NEW.username AND message_id=NEW.message_id;
END;
CREATE TRIGGER IF NOT EXISTS adaptive_label_withdraw AFTER DELETE ON feedback BEGIN
 DELETE FROM adaptive_labels WHERE username=OLD.username AND message_id=OLD.message_id;
END;

-- Dataset purpose is fixed at sampling time. Legacy batches remain evaluation only.
CREATE TABLE IF NOT EXISTS quality_purposes(
 batch_id TEXT PRIMARY KEY REFERENCES quality_batches(id) ON DELETE CASCADE,
 purpose TEXT NOT NULL CHECK(purpose IN ('development','regression','holdout')),
 cohort TEXT NOT NULL DEFAULT ''
);
-- Review labels must never be changed by operational feedback.
DROP TRIGGER IF EXISTS quality_label_invalidate;
-- Explicit references survive batch deletion while their message metadata exists.
CREATE TABLE IF NOT EXISTS quality_reserved(
 message_id TEXT PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
 created INTEGER NOT NULL, reason TEXT NOT NULL
);
CREATE VIEW IF NOT EXISTS quality_protected_messages AS
 SELECT message_id FROM quality_reserved UNION
 SELECT x.message_id FROM quality_members x LEFT JOIN quality_purposes p ON p.batch_id=x.batch_id
 WHERE COALESCE(p.purpose,'regression')!='development';
-- All evaluation labels are isolated from implicit/periodic learning and sender trust.
CREATE VIEW IF NOT EXISTS training_feedback AS
 SELECT f.* FROM feedback f WHERE NOT EXISTS(SELECT 1 FROM quality_labels q WHERE q.message_id=f.message_id)
 AND NOT EXISTS(SELECT 1 FROM quality_protected_messages p WHERE p.message_id=f.message_id);
CREATE TABLE IF NOT EXISTS quality_jobs(
 id TEXT PRIMARY KEY, username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
 batch_id TEXT NOT NULL REFERENCES quality_batches(id) ON DELETE CASCADE,
 operation TEXT NOT NULL CHECK(operation IN ('train','compare','evaluate')),
 candidate_id TEXT,
 status TEXT NOT NULL CHECK(status IN ('queued','running','complete','insufficient_labels','failed','cancelled','interrupted')),
 created INTEGER NOT NULL, started INTEGER, finished INTEGER,
 report TEXT, model_sha256 TEXT
);
CREATE INDEX IF NOT EXISTS quality_job_queue ON quality_jobs(status,created);
CREATE TABLE IF NOT EXISTS quality_worker_status(
 id INTEGER PRIMARY KEY CHECK(id=1), heartbeat INTEGER NOT NULL, build TEXT NOT NULL
);

-- Curated references are labelled as such; never pretend they are a traffic draw.
CREATE TABLE IF NOT EXISTS quality_reference_sets(
 batch_id TEXT PRIMARY KEY REFERENCES quality_batches(id) ON DELETE CASCADE,
 provenance TEXT NOT NULL
);
