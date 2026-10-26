CREATE TABLE identity_connections (
 source_id TEXT PRIMARY KEY,
 record TEXT NOT NULL CHECK(json_valid(record) AND length(CAST(record AS BLOB)) <= 65536)
);
