CREATE TABLE IF NOT EXISTS ha_local(
 message_id TEXT PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
 generation INTEGER NOT NULL, acked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS ha_remote(
 owner TEXT NOT NULL, id TEXT NOT NULL, generation INTEGER NOT NULL,
 manifest TEXT NOT NULL, body_hash TEXT, body_bytes INTEGER NOT NULL,
 body_present INTEGER NOT NULL, updated INTEGER NOT NULL,
 PRIMARY KEY(owner,id)
);
CREATE TABLE IF NOT EXISTS ha_blobs(
 owner TEXT NOT NULL,id TEXT NOT NULL,hash TEXT NOT NULL,bytes INTEGER NOT NULL,
 present INTEGER NOT NULL DEFAULT 1,updated INTEGER NOT NULL,PRIMARY KEY(owner,id)
);
CREATE TABLE IF NOT EXISTS ha_recoveries(
 owner TEXT NOT NULL, id TEXT NOT NULL, generation INTEGER NOT NULL,
 recovered INTEGER NOT NULL, disposition TEXT NOT NULL, PRIMARY KEY(owner,id)
);
CREATE TRIGGER IF NOT EXISTS ha_mail_insert AFTER INSERT ON messages
WHEN EXISTS(SELECT 1 FROM cluster_state WHERE key='ha_required') BEGIN
 INSERT OR IGNORE INTO ha_local VALUES(NEW.id,1,0);
END;
CREATE TRIGGER IF NOT EXISTS ha_origin_insert AFTER INSERT ON cluster_origin BEGIN
 DELETE FROM ha_local WHERE message_id=NEW.message_id;
END;
CREATE TRIGGER IF NOT EXISTS ha_mail_update AFTER UPDATE OF raw_present,scan ON messages BEGIN
 UPDATE ha_local SET generation=generation+1 WHERE message_id=NEW.id;
END;
CREATE TRIGGER IF NOT EXISTS ha_delivery_insert AFTER INSERT ON deliveries BEGIN
 UPDATE ha_local SET generation=generation+1 WHERE message_id=NEW.message_id;
END;
CREATE TRIGGER IF NOT EXISTS ha_delivery_update AFTER UPDATE ON deliveries BEGIN
 UPDATE ha_local SET generation=generation+1 WHERE message_id=NEW.message_id;
END;
CREATE TRIGGER IF NOT EXISTS ha_policy_update AFTER UPDATE ON delivery_policy BEGIN
 UPDATE ha_local SET generation=generation+1 WHERE message_id=(SELECT message_id FROM deliveries WHERE id=NEW.delivery_id);
END;
