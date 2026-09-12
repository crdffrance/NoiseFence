-- Additive to v2. Only already-retained metadata is indexed. No body, attachment,
-- recipient, SMTP transcript, LLM reasoning or URL content enters the index.
CREATE VIRTUAL TABLE message_search USING fts5(
 subject, sender, rules, tokenize='unicode61 remove_diacritics 2', prefix='2 3'
);
-- Remove obsolete index tokens as well as live rows during retention cleanup.
INSERT INTO message_search(message_search,rank) VALUES('secure-delete',1);
CREATE VIEW message_search_source AS
 SELECT m.rowid AS rowid, substr(json_extract(CASE WHEN json_valid(m.scan) THEN m.scan ELSE '{}' END,'$.subject'),1,4096) AS subject,
 substr(m.sender,1,1024) AS sender,
 substr(COALESCE((SELECT group_concat(json_extract(CASE WHEN type='object' THEN value ELSE '{}' END,'$.id'),' ') FROM json_each(CASE WHEN json_valid(m.scan) THEN m.scan ELSE '{}' END,'$.reasons')),''),1,16384) AS rules
 FROM messages m;
INSERT INTO message_search(rowid,subject,sender,rules) SELECT rowid,subject,sender,rules FROM message_search_source;
CREATE TRIGGER message_search_insert AFTER INSERT ON messages BEGIN
 INSERT INTO message_search(rowid,subject,sender,rules) SELECT rowid,subject,sender,rules FROM message_search_source WHERE rowid=NEW.rowid;
END;
CREATE TRIGGER message_search_update AFTER UPDATE OF scan,sender ON messages BEGIN
 DELETE FROM message_search WHERE rowid=OLD.rowid;
 INSERT INTO message_search(rowid,subject,sender,rules) SELECT rowid,subject,sender,rules FROM message_search_source WHERE rowid=NEW.rowid;
END;
CREATE TRIGGER message_search_delete AFTER DELETE ON messages BEGIN
 DELETE FROM message_search WHERE rowid=OLD.rowid;
END;
