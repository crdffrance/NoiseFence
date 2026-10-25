CREATE TABLE noisefence.identity_connections (
 source_id text PRIMARY KEY,
 record jsonb NOT NULL CHECK(jsonb_typeof(record)='object' AND octet_length(record::text) <= 65536)
);
