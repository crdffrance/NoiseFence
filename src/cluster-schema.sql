-- Cluster metadata never transfers ownership of a durable SMTP queue.
CREATE TABLE IF NOT EXISTS cluster_nodes(
 id TEXT PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL,
 enabled INTEGER NOT NULL DEFAULT 1, created INTEGER NOT NULL,
 last_seen INTEGER, applied_revision INTEGER, applied_digest TEXT,
 status TEXT NOT NULL DEFAULT '{}', version INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS cluster_state(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS cluster_origin(
 message_id TEXT PRIMARY KEY REFERENCES messages(id) ON DELETE CASCADE,
 node_id TEXT NOT NULL, remote_id TEXT NOT NULL, updated INTEGER NOT NULL,
 raw_present INTEGER NOT NULL, remote_version INTEGER NOT NULL, UNIQUE(node_id,remote_id)
);
CREATE INDEX IF NOT EXISTS cluster_origin_node ON cluster_origin(node_id,updated);
CREATE TABLE IF NOT EXISTS cluster_dirty(message_id TEXT PRIMARY KEY, generation INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS cluster_sequence(id INTEGER PRIMARY KEY CHECK(id=1),value INTEGER NOT NULL);
INSERT OR IGNORE INTO cluster_sequence VALUES(1,0);
CREATE TRIGGER IF NOT EXISTS cluster_mail_insert AFTER INSERT ON messages
WHEN EXISTS(SELECT 1 FROM cluster_state WHERE key='role' AND value='worker') AND NOT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=NEW.id) BEGIN
 UPDATE cluster_sequence SET value=value+1;
 INSERT OR REPLACE INTO cluster_dirty VALUES(NEW.id,(SELECT value FROM cluster_sequence));
END;
CREATE TRIGGER IF NOT EXISTS cluster_mail_update AFTER UPDATE OF raw_present,scan ON messages
WHEN EXISTS(SELECT 1 FROM cluster_state WHERE key='role' AND value='worker') AND NOT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=NEW.id) BEGIN
 UPDATE cluster_sequence SET value=value+1;
 INSERT OR REPLACE INTO cluster_dirty VALUES(NEW.id,(SELECT value FROM cluster_sequence));
END;
CREATE TRIGGER IF NOT EXISTS cluster_delivery_insert AFTER INSERT ON deliveries
WHEN EXISTS(SELECT 1 FROM cluster_state WHERE key='role' AND value='worker') AND NOT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=NEW.message_id) BEGIN
 UPDATE cluster_sequence SET value=value+1;
 INSERT OR REPLACE INTO cluster_dirty VALUES(NEW.message_id,(SELECT value FROM cluster_sequence));
END;
CREATE TRIGGER IF NOT EXISTS cluster_delivery_update AFTER UPDATE ON deliveries
WHEN EXISTS(SELECT 1 FROM cluster_state WHERE key='role' AND value='worker') AND NOT EXISTS(SELECT 1 FROM cluster_origin WHERE message_id=NEW.message_id) BEGIN
 UPDATE cluster_sequence SET value=value+1;
 INSERT OR REPLACE INTO cluster_dirty VALUES(NEW.message_id,(SELECT value FROM cluster_sequence));
END;
CREATE TRIGGER IF NOT EXISTS cluster_mail_delete AFTER DELETE ON messages BEGIN
 DELETE FROM cluster_dirty WHERE message_id=OLD.id;
END;
CREATE TABLE IF NOT EXISTS cluster_commands(
 id TEXT PRIMARY KEY, node_id TEXT NOT NULL, message_id TEXT NOT NULL,
 recipient TEXT NOT NULL, command TEXT NOT NULL, username TEXT NOT NULL,
 created INTEGER NOT NULL, expires INTEGER NOT NULL, result TEXT,
 finished INTEGER
);
CREATE UNIQUE INDEX IF NOT EXISTS cluster_pending_command ON cluster_commands(node_id,message_id,recipient) WHERE finished IS NULL;
CREATE TABLE IF NOT EXISTS cluster_command_receipts(id TEXT PRIMARY KEY,result TEXT NOT NULL,created INTEGER NOT NULL);
