-- Separate bounded stream: a large recipient history cannot block message metadata.
CREATE TABLE IF NOT EXISTS management_log_outbox(
 log_id INTEGER PRIMARY KEY, generation INTEGER NOT NULL CHECK(generation>0),
 message_id TEXT NOT NULL, recipient TEXT NOT NULL,
 deleted INTEGER NOT NULL CHECK(deleted IN (0,1))
);
CREATE INDEX IF NOT EXISTS management_log_outbox_sequence ON management_log_outbox(generation);
CREATE INDEX IF NOT EXISTS management_log_outbox_message ON management_log_outbox(message_id);
CREATE TRIGGER IF NOT EXISTS management_log_insert AFTER INSERT ON delivery_attempts
WHEN EXISTS(SELECT 1 FROM management_journal WHERE id=1)
 AND EXISTS(SELECT 1 FROM deliveries d JOIN messages m ON m.id=d.message_id WHERE d.id=NEW.delivery_id
  AND NOT EXISTS(SELECT 1 FROM cluster_origin o WHERE o.message_id=m.id))
BEGIN
 UPDATE management_journal SET sequence=sequence+1 WHERE id=1;
 INSERT INTO management_log_outbox(log_id,generation,message_id,recipient,deleted)
 SELECT NEW.id,j.sequence,d.message_id,d.address,0 FROM management_journal j JOIN deliveries d ON d.id=NEW.delivery_id WHERE j.id=1
 ON CONFLICT(log_id) DO UPDATE SET generation=excluded.generation,message_id=excluded.message_id,recipient=excluded.recipient,deleted=0;
END;
CREATE TRIGGER IF NOT EXISTS management_log_update AFTER UPDATE ON delivery_attempts
WHEN EXISTS(SELECT 1 FROM management_journal WHERE id=1)
 AND EXISTS(SELECT 1 FROM deliveries d JOIN messages m ON m.id=d.message_id WHERE d.id=NEW.delivery_id
  AND NOT EXISTS(SELECT 1 FROM cluster_origin o WHERE o.message_id=m.id))
BEGIN
 UPDATE management_journal SET sequence=sequence+1 WHERE id=1;
 INSERT INTO management_log_outbox(log_id,generation,message_id,recipient,deleted)
 SELECT NEW.id,j.sequence,d.message_id,d.address,0 FROM management_journal j JOIN deliveries d ON d.id=NEW.delivery_id WHERE j.id=1
 ON CONFLICT(log_id) DO UPDATE SET generation=excluded.generation,message_id=excluded.message_id,recipient=excluded.recipient,deleted=0;
END;
CREATE TRIGGER IF NOT EXISTS management_log_delete BEFORE DELETE ON delivery_attempts
WHEN EXISTS(SELECT 1 FROM management_journal WHERE id=1)
 AND EXISTS(SELECT 1 FROM deliveries d JOIN messages m ON m.id=d.message_id WHERE d.id=OLD.delivery_id
  AND NOT EXISTS(SELECT 1 FROM cluster_origin o WHERE o.message_id=m.id))
BEGIN
 UPDATE management_journal SET sequence=sequence+1 WHERE id=1;
 INSERT INTO management_log_outbox(log_id,generation,message_id,recipient,deleted)
 SELECT OLD.id,j.sequence,d.message_id,d.address,1 FROM management_journal j JOIN deliveries d ON d.id=OLD.delivery_id WHERE j.id=1
 ON CONFLICT(log_id) DO UPDATE SET generation=excluded.generation,deleted=1;
END;
CREATE TRIGGER IF NOT EXISTS management_logs_message_delete BEFORE DELETE ON messages BEGIN
 DELETE FROM management_log_outbox WHERE message_id=OLD.id;
END;
CREATE TRIGGER IF NOT EXISTS management_logs_remote_insert AFTER INSERT ON cluster_origin BEGIN
 DELETE FROM management_log_outbox WHERE message_id=NEW.message_id;
END;
