CREATE TABLE noisefence.identity_scim_sources (
 source_id TEXT PRIMARY KEY REFERENCES noisefence.identity_connections(source_id),
 source_sha256 TEXT NOT NULL,
 sequence BIGINT NOT NULL DEFAULT 0 CHECK(sequence>=0),
 users BIGINT NOT NULL DEFAULT 0 CHECK(users BETWEEN 0 AND 20000),
 groups BIGINT NOT NULL DEFAULT 0 CHECK(groups BETWEEN 0 AND 5000),
 memberships BIGINT NOT NULL DEFAULT 0 CHECK(memberships BETWEEN 0 AND 100000),
 reserved_bytes BIGINT NOT NULL DEFAULT 0 CHECK(reserved_bytes BETWEEN 0 AND 67108864),
 modified BIGINT NOT NULL CHECK(modified>0),
 window_started BIGINT NOT NULL CHECK(window_started>0),
 requests BIGINT NOT NULL DEFAULT 0 CHECK(requests BETWEEN 0 AND 600)
);
CREATE TABLE noisefence.identity_scim_resources (
 source_id TEXT NOT NULL REFERENCES noisefence.identity_scim_sources(source_id),
 id TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('User','Group')),
 user_name_key TEXT,
 external_id TEXT,
 display_name_key TEXT,
 active BIGINT CHECK(active IN (0,1)),
 member_count BIGINT NOT NULL CHECK(member_count BETWEEN 0 AND 4096),
 record TEXT NOT NULL CHECK(jsonb_typeof(record::jsonb)='object' AND octet_length(record) <= 1049600),
 PRIMARY KEY(source_id,id),
 UNIQUE(source_id,id,kind),
 UNIQUE(source_id,user_name_key)
);
CREATE INDEX identity_scim_kind ON noisefence.identity_scim_resources(source_id,kind,id);
CREATE INDEX identity_scim_external ON noisefence.identity_scim_resources(source_id,kind,external_id,id);
CREATE INDEX identity_scim_display ON noisefence.identity_scim_resources(source_id,kind,display_name_key,id);
CREATE INDEX identity_scim_active ON noisefence.identity_scim_resources(source_id,kind,active,id);
CREATE TABLE noisefence.identity_scim_members (
 source_id TEXT NOT NULL,
 group_id TEXT NOT NULL,
 group_kind TEXT NOT NULL DEFAULT 'Group' CHECK(group_kind='Group'),
 member_id TEXT NOT NULL,
 member_kind TEXT NOT NULL CHECK(member_kind IN ('User','Group')),
 PRIMARY KEY(source_id,group_id,member_id),
 CHECK(group_id<>member_id),
 FOREIGN KEY(source_id,group_id,group_kind) REFERENCES noisefence.identity_scim_resources(source_id,id,kind),
 FOREIGN KEY(source_id,member_id,member_kind) REFERENCES noisefence.identity_scim_resources(source_id,id,kind)
);
CREATE INDEX identity_scim_reverse ON noisefence.identity_scim_members(source_id,member_id,group_id);
