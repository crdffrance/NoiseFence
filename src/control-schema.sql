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
