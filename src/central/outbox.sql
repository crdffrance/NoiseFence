-- Enabled explicitly when a node joins central management. No network I/O.
CREATE TABLE IF NOT EXISTS management_journal(
 id INTEGER PRIMARY KEY CHECK(id=1), node TEXT NOT NULL, epoch TEXT NOT NULL,
 sequence INTEGER NOT NULL CHECK(sequence>=0)
);
CREATE TABLE IF NOT EXISTS management_outbox(
 message_id TEXT PRIMARY KEY, generation INTEGER NOT NULL CHECK(generation>0),
 deleted INTEGER NOT NULL CHECK(deleted IN (0,1))
);
CREATE INDEX IF NOT EXISTS management_outbox_sequence ON management_outbox(generation);
CREATE TABLE IF NOT EXISTS management_command_bindings(
 id TEXT PRIMARY KEY, epoch TEXT NOT NULL, digest TEXT NOT NULL, created INTEGER NOT NULL,
 acknowledged INTEGER NOT NULL DEFAULT 0 CHECK(acknowledged IN (0,1))
);
CREATE TRIGGER IF NOT EXISTS management_message_insert AFTER INSERT ON messages
WHEN EXISTS(SELECT 1 FROM management_journal WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=NEW.id)

BEGIN
 UPDATE management_journal SET sequence=sequence+1 WHERE id=1;
 INSERT INTO management_outbox(message_id,generation,deleted)
 SELECT NEW.id,sequence,0 FROM management_journal WHERE id=1
 ON CONFLICT(message_id) DO UPDATE SET generation=excluded.generation,deleted=excluded.deleted;
END;
CREATE TRIGGER IF NOT EXISTS management_message_update AFTER UPDATE ON messages
WHEN EXISTS(SELECT 1 FROM management_journal WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=NEW.id)

BEGIN
 UPDATE management_journal SET sequence=sequence+1 WHERE id=1;
 INSERT INTO management_outbox(message_id,generation,deleted)
 SELECT NEW.id,sequence,0 FROM management_journal WHERE id=1
 ON CONFLICT(message_id) DO UPDATE SET generation=excluded.generation,deleted=excluded.deleted;
END;
CREATE TRIGGER IF NOT EXISTS management_message_delete BEFORE DELETE ON messages
WHEN EXISTS(SELECT 1 FROM management_journal WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=OLD.id)

BEGIN
 UPDATE management_journal SET sequence=sequence+1 WHERE id=1;
 INSERT INTO management_outbox(message_id,generation,deleted)
 SELECT OLD.id,sequence,1 FROM management_journal WHERE id=1
 ON CONFLICT(message_id) DO UPDATE SET generation=excluded.generation,deleted=excluded.deleted;
END;
CREATE TRIGGER IF NOT EXISTS management_delivery_insert AFTER INSERT ON deliveries
WHEN EXISTS(SELECT 1 FROM management_journal WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=NEW.message_id)
 AND EXISTS(SELECT 1 FROM messages WHERE id=NEW.message_id)
BEGIN
 UPDATE management_journal SET sequence=sequence+1 WHERE id=1;
 INSERT INTO management_outbox(message_id,generation,deleted)
 SELECT NEW.message_id,sequence,0 FROM management_journal WHERE id=1
 ON CONFLICT(message_id) DO UPDATE SET generation=excluded.generation,deleted=excluded.deleted;
END;
CREATE TRIGGER IF NOT EXISTS management_delivery_update AFTER UPDATE ON deliveries
WHEN EXISTS(SELECT 1 FROM management_journal WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=NEW.message_id)
 AND EXISTS(SELECT 1 FROM messages WHERE id=NEW.message_id)
BEGIN
 UPDATE management_journal SET sequence=sequence+1 WHERE id=1;
 INSERT INTO management_outbox(message_id,generation,deleted)
 SELECT NEW.message_id,sequence,0 FROM management_journal WHERE id=1
 ON CONFLICT(message_id) DO UPDATE SET generation=excluded.generation,deleted=excluded.deleted;
END;
CREATE TRIGGER IF NOT EXISTS management_delivery_delete AFTER DELETE ON deliveries
WHEN EXISTS(SELECT 1 FROM management_journal WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=OLD.message_id)
 AND EXISTS(SELECT 1 FROM messages WHERE id=OLD.message_id)
BEGIN
 UPDATE management_journal SET sequence=sequence+1 WHERE id=1;
 INSERT INTO management_outbox(message_id,generation,deleted)
 SELECT OLD.message_id,sequence,0 FROM management_journal WHERE id=1
 ON CONFLICT(message_id) DO UPDATE SET generation=excluded.generation,deleted=excluded.deleted;
END;
CREATE TRIGGER IF NOT EXISTS management_delivery_policy_insert AFTER INSERT ON delivery_policy
WHEN EXISTS(SELECT 1 FROM management_journal WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=(SELECT message_id FROM deliveries WHERE id=NEW.delivery_id))
 AND EXISTS(SELECT 1 FROM messages WHERE id=(SELECT message_id FROM deliveries WHERE id=NEW.delivery_id))
BEGIN
 UPDATE management_journal SET sequence=sequence+1 WHERE id=1;
 INSERT INTO management_outbox(message_id,generation,deleted)
 SELECT (SELECT message_id FROM deliveries WHERE id=NEW.delivery_id),sequence,0 FROM management_journal WHERE id=1
 ON CONFLICT(message_id) DO UPDATE SET generation=excluded.generation,deleted=excluded.deleted;
END;
CREATE TRIGGER IF NOT EXISTS management_delivery_policy_update AFTER UPDATE ON delivery_policy
WHEN EXISTS(SELECT 1 FROM management_journal WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=(SELECT message_id FROM deliveries WHERE id=NEW.delivery_id))
 AND EXISTS(SELECT 1 FROM messages WHERE id=(SELECT message_id FROM deliveries WHERE id=NEW.delivery_id))
BEGIN
 UPDATE management_journal SET sequence=sequence+1 WHERE id=1;
 INSERT INTO management_outbox(message_id,generation,deleted)
 SELECT (SELECT message_id FROM deliveries WHERE id=NEW.delivery_id),sequence,0 FROM management_journal WHERE id=1
 ON CONFLICT(message_id) DO UPDATE SET generation=excluded.generation,deleted=excluded.deleted;
END;
CREATE TRIGGER IF NOT EXISTS management_delivery_policy_delete AFTER DELETE ON delivery_policy
WHEN EXISTS(SELECT 1 FROM management_journal WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=(SELECT message_id FROM deliveries WHERE id=OLD.delivery_id))
 AND EXISTS(SELECT 1 FROM messages WHERE id=(SELECT message_id FROM deliveries WHERE id=OLD.delivery_id))
BEGIN
 UPDATE management_journal SET sequence=sequence+1 WHERE id=1;
 INSERT INTO management_outbox(message_id,generation,deleted)
 SELECT (SELECT message_id FROM deliveries WHERE id=OLD.delivery_id),sequence,0 FROM management_journal WHERE id=1
 ON CONFLICT(message_id) DO UPDATE SET generation=excluded.generation,deleted=excluded.deleted;
END;
CREATE TRIGGER IF NOT EXISTS management_delivery_filtering_insert AFTER INSERT ON delivery_filtering
WHEN EXISTS(SELECT 1 FROM management_journal WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=(SELECT message_id FROM deliveries WHERE id=NEW.delivery_id))
 AND EXISTS(SELECT 1 FROM messages WHERE id=(SELECT message_id FROM deliveries WHERE id=NEW.delivery_id))
BEGIN
 UPDATE management_journal SET sequence=sequence+1 WHERE id=1;
 INSERT INTO management_outbox(message_id,generation,deleted)
 SELECT (SELECT message_id FROM deliveries WHERE id=NEW.delivery_id),sequence,0 FROM management_journal WHERE id=1
 ON CONFLICT(message_id) DO UPDATE SET generation=excluded.generation,deleted=excluded.deleted;
END;
CREATE TRIGGER IF NOT EXISTS management_delivery_filtering_update AFTER UPDATE ON delivery_filtering
WHEN EXISTS(SELECT 1 FROM management_journal WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=(SELECT message_id FROM deliveries WHERE id=NEW.delivery_id))
 AND EXISTS(SELECT 1 FROM messages WHERE id=(SELECT message_id FROM deliveries WHERE id=NEW.delivery_id))
BEGIN
 UPDATE management_journal SET sequence=sequence+1 WHERE id=1;
 INSERT INTO management_outbox(message_id,generation,deleted)
 SELECT (SELECT message_id FROM deliveries WHERE id=NEW.delivery_id),sequence,0 FROM management_journal WHERE id=1
 ON CONFLICT(message_id) DO UPDATE SET generation=excluded.generation,deleted=excluded.deleted;
END;
CREATE TRIGGER IF NOT EXISTS management_delivery_filtering_delete AFTER DELETE ON delivery_filtering
WHEN EXISTS(SELECT 1 FROM management_journal WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=(SELECT message_id FROM deliveries WHERE id=OLD.delivery_id))
 AND EXISTS(SELECT 1 FROM messages WHERE id=(SELECT message_id FROM deliveries WHERE id=OLD.delivery_id))
BEGIN
 UPDATE management_journal SET sequence=sequence+1 WHERE id=1;
 INSERT INTO management_outbox(message_id,generation,deleted)
 SELECT (SELECT message_id FROM deliveries WHERE id=OLD.delivery_id),sequence,0 FROM management_journal WHERE id=1
 ON CONFLICT(message_id) DO UPDATE SET generation=excluded.generation,deleted=excluded.deleted;
END;
CREATE TRIGGER IF NOT EXISTS management_delivery_attempts_insert AFTER INSERT ON delivery_attempts
WHEN EXISTS(SELECT 1 FROM management_journal WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=(SELECT message_id FROM deliveries WHERE id=NEW.delivery_id))
 AND EXISTS(SELECT 1 FROM messages WHERE id=(SELECT message_id FROM deliveries WHERE id=NEW.delivery_id))
BEGIN
 UPDATE management_journal SET sequence=sequence+1 WHERE id=1;
 INSERT INTO management_outbox(message_id,generation,deleted)
 SELECT (SELECT message_id FROM deliveries WHERE id=NEW.delivery_id),sequence,0 FROM management_journal WHERE id=1
 ON CONFLICT(message_id) DO UPDATE SET generation=excluded.generation,deleted=excluded.deleted;
END;
CREATE TRIGGER IF NOT EXISTS management_delivery_attempts_update AFTER UPDATE ON delivery_attempts
WHEN EXISTS(SELECT 1 FROM management_journal WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=(SELECT message_id FROM deliveries WHERE id=NEW.delivery_id))
 AND EXISTS(SELECT 1 FROM messages WHERE id=(SELECT message_id FROM deliveries WHERE id=NEW.delivery_id))
BEGIN
 UPDATE management_journal SET sequence=sequence+1 WHERE id=1;
 INSERT INTO management_outbox(message_id,generation,deleted)
 SELECT (SELECT message_id FROM deliveries WHERE id=NEW.delivery_id),sequence,0 FROM management_journal WHERE id=1
 ON CONFLICT(message_id) DO UPDATE SET generation=excluded.generation,deleted=excluded.deleted;
END;
CREATE TRIGGER IF NOT EXISTS management_delivery_attempts_delete AFTER DELETE ON delivery_attempts
WHEN EXISTS(SELECT 1 FROM management_journal WHERE id=1)
 AND NOT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=(SELECT message_id FROM deliveries WHERE id=OLD.delivery_id))
 AND EXISTS(SELECT 1 FROM messages WHERE id=(SELECT message_id FROM deliveries WHERE id=OLD.delivery_id))
BEGIN
 UPDATE management_journal SET sequence=sequence+1 WHERE id=1;
 INSERT INTO management_outbox(message_id,generation,deleted)
 SELECT (SELECT message_id FROM deliveries WHERE id=OLD.delivery_id),sequence,0 FROM management_journal WHERE id=1
 ON CONFLICT(message_id) DO UPDATE SET generation=excluded.generation,deleted=excluded.deleted;
END;
-- The existing cluster history importer inserts the origin in the same
-- transaction as the copied message. A copy is never a local queue owner.
CREATE TRIGGER IF NOT EXISTS management_remote_origin AFTER INSERT ON cluster_origin BEGIN
 DELETE FROM management_outbox WHERE message_id=NEW.message_id;
END;
