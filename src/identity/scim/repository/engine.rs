use super::{
    Command, EDGE_BYTES, Inventory, MAX_BYTES, REQUESTS_PER_MINUTE, Reply, Stage,
    database::{Database, Param, Row, scalar},
    revision,
};
use crate::identity::{
    connections::Record,
    directory::{Member, Source},
    scim::{self, Data, ListQuery, Resource, ResourceType},
};
use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, BTreeSet};
const NOT_FOUND: scim::Error = scim::Error::new(404, "", "SCIM resource not found.");
const CONFLICT: scim::Error = scim::Error::new(
    409,
    "uniqueness",
    "SCIM userName is already assigned within this source.",
);
fn text(v: Option<String>) -> Param {
    Param::Text(v)
}
fn kind(value: &str) -> Result<ResourceType> {
    match value {
        "User" => Ok(ResourceType::User),
        "Group" => Ok(ResourceType::Group),
        _ => anyhow::bail!("Invalid SCIM resource kind"),
    }
}
fn edge(member: &Member) -> (&str, &str) {
    match member {
        Member::Person(id) => (id, "User"),
        Member::Group(id) => (id, "Group"),
    }
}
fn parse_edge(row: &Row, id_column: usize, kind_column: usize) -> Result<Member> {
    let id = row.text(id_column)?.to_owned();
    Ok(match kind(row.text(kind_column)?)? {
        ResourceType::User => Member::Person(id),
        ResourceType::Group => Member::Group(id),
    })
}
pub(super) async fn stage(db: &mut impl Database, record: &Record, now: i64) -> Result<Stage> {
    let source = &record.metadata.source;
    let digest = scim::staging::source_digest(source)?;
    db.execute("INSERT INTO identity_scim_sources(source_id,source_sha256,modified,window_started) VALUES(?1,?2,?3,?3) ON CONFLICT(source_id) DO NOTHING",&[source.id.as_str().into(),digest.as_str().into(),now.into()]).await?;
    let rows=db.query("SELECT source_sha256,sequence,users,groups,memberships,reserved_bytes,modified FROM identity_scim_sources WHERE source_id=?1",&[source.id.as_str().into()]).await?;
    let row = rows.first().context("Missing SCIM source")?;
    ensure!(row.text(0)? == digest, "SCIM source binding changed");
    let counts = (2..=5)
        .map(|i| usize::try_from(row.integer(i)?).context("Invalid SCIM counters"))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        counts[0] <= 20000 && counts[1] <= 5000 && counts[2] <= 100000 && counts[3] <= MAX_BYTES,
        "Invalid SCIM counters"
    );
    let modified = row.integer(6)?;
    ensure!(
        modified > 0 && modified <= now,
        "SCIM staging clock moved backwards"
    );
    Ok(Stage {
        revision: revision(record, row.integer(1)?)?,
        users: counts[0],
        groups: counts[1],
        memberships: counts[2],
        reserved_bytes: counts[3],
        modified,
    })
}
async fn charge(db: &mut impl Database, source: &str, now: i64) -> Result<()> {
    let rows = db
        .query(
            "SELECT window_started,requests FROM identity_scim_sources WHERE source_id=?1",
            &[source.into()],
        )
        .await?;
    let row = rows.first().context("Missing SCIM rate state")?;
    let start = row.integer(0)?;
    let count = row.integer(1)?;
    ensure!(
        start <= now && (0..=REQUESTS_PER_MINUTE).contains(&count),
        "Invalid SCIM rate state"
    );
    let reset = now - start >= 60;
    if !reset && count >= REQUESTS_PER_MINUTE {
        return Err(
            scim::Error::new(429, "", "SCIM source request limit reached; retry later.").into(),
        );
    }
    db.execute(
        "UPDATE identity_scim_sources SET window_started=?2,requests=?3 WHERE source_id=?1",
        &[
            source.into(),
            (if reset { now } else { start }).into(),
            (if reset { 1 } else { count + 1 }).into(),
        ],
    )
    .await?;
    Ok(())
}
pub(crate) async fn execute(
    db: &mut impl Database,
    record: &Record,
    command: Command,
    now: i64,
) -> Result<scim::Result<Reply>> {
    let stage = stage(db, record, now).await?;
    charge(db, &record.metadata.source.id, now).await?;
    // Keep the charge on client errors, but roll back every partial mutation.
    // Infrastructure errors abort the enclosing transaction instead.
    db.execute("SAVEPOINT scim_change", &[]).await?;
    let result = dispatch(db, &record.metadata.source, &stage, command, now).await;
    let outcome = match result {
        Ok(reply) => Ok(reply),
        Err(error) => match error.downcast_ref::<scim::Error>() {
            Some(value) => {
                let value = *value;
                db.execute("ROLLBACK TO SAVEPOINT scim_change", &[]).await?;
                Err(value)
            }
            None => return Err(error),
        },
    };
    db.execute("RELEASE SAVEPOINT scim_change", &[]).await?;
    Ok(outcome)
}
async fn dispatch(
    db: &mut impl Database,
    source: &Source,
    stage: &Stage,
    command: Command,
    now: i64,
) -> Result<Reply> {
    match command {
        Command::Authenticate => Ok(Reply::Status(stage.clone())),
        Command::Get { kind, id } => {
            Ok(Reply::Resource(Box::new(get(db, source, kind, &id).await?)))
        }
        Command::List { kind, query } => list(db, source, kind, &query).await,
        Command::Create { kind, body } => {
            let next = Resource::create(source, Data::parse(kind, &body)?, now)?;
            put(db, source, stage, None, &next, now).await?;
            Ok(Reply::Resource(Box::new(next)))
        }
        Command::Replace {
            kind,
            id,
            body,
            expected,
        } => {
            let old = get(db, source, kind, &id).await?;
            let next = old.replace(&body, expected.as_deref(), now)?;
            put(db, source, stage, Some(&old), &next, now).await?;
            Ok(Reply::Resource(Box::new(next)))
        }
        Command::Patch {
            kind,
            id,
            body,
            expected,
        } => {
            let old = get(db, source, kind, &id).await?;
            let next = old.patch(&body, expected.as_deref(), now)?;
            put(db, source, stage, Some(&old), &next, now).await?;
            Ok(Reply::Resource(Box::new(next)))
        }
        Command::Delete { kind, id, expected } => {
            let old = get(db, source, kind, &id).await?;
            old.precondition(expected.as_deref())?;
            delete(db, source, stage, &old, now).await?;
            Ok(Reply::Deleted)
        }
    }
}
fn base(row: &Row, source: &Source) -> Result<Resource> {
    let result = Resource::decode(row.text(2)?.as_bytes(), source)?;
    ensure!(
        result.data().kind().name() == row.text(0)? && result.data().members().is_empty(),
        "Inconsistent SCIM resource row"
    );
    Ok(result)
}
async fn hydrate(db: &mut impl Database, source: &Source, row: &Row) -> Result<Resource> {
    let base = base(row, source)?;
    let rows=db.query("SELECT member_id,member_kind FROM identity_scim_members WHERE source_id=?1 AND group_id=?2 ORDER BY member_id LIMIT 4097",&[source.id.as_str().into(),base.id().into()]).await?;
    ensure!(
        rows.len() <= scim::MAX_MEMBERS && rows.len() as i64 == row.integer(1)?,
        "Inconsistent SCIM memberships"
    );
    let members = rows
        .iter()
        .map(|r| parse_edge(r, 0, 1))
        .collect::<Result<BTreeSet<_>>>()?;
    Ok(base.with_stored_members(source, members)?)
}
async fn get(
    db: &mut impl Database,
    source: &Source,
    kind: ResourceType,
    id: &str,
) -> Result<Resource> {
    if !scim::resource::id(id) {
        return Err(NOT_FOUND.into());
    }
    let rows=db.query("SELECT kind,member_count,record FROM identity_scim_resources WHERE source_id=?1 AND id=?2 AND kind=?3",&[source.id.as_str().into(),id.into(),kind.name().into()]).await?;
    hydrate(db, source, rows.first().ok_or(NOT_FOUND)?).await
}
async fn list(
    db: &mut impl Database,
    source: &Source,
    kind: ResourceType,
    query: &ListQuery,
) -> Result<Reply> {
    if query.count > scim::MAX_PAGE || query.start_index == 0 {
        return Err(scim::INVALID.into());
    }
    let mut params = vec![source.id.as_str().into(), kind.name().into()];
    let mut clause = String::from("source_id=?1 AND kind=?2");
    if let Some(filter) = &query.filter {
        let (key, value) = filter.parts();
        let (column, param) = match key {
            "id" => ("id", value.as_str().context("Invalid ID filter")?.into()),
            "externalid" => (
                "external_id",
                value.as_str().context("Invalid external ID filter")?.into(),
            ),
            "displayname" => (
                "display_name_key",
                value
                    .as_str()
                    .context("Invalid name filter")?
                    .to_lowercase()
                    .into(),
            ),
            "username" if kind == ResourceType::User => (
                "user_name_key",
                value
                    .as_str()
                    .context("Invalid login filter")?
                    .to_ascii_lowercase()
                    .into(),
            ),
            "active" if kind == ResourceType::User => (
                "active",
                i64::from(value.as_bool().context("Invalid activity filter")?).into(),
            ),
            _ => return Err(scim::INVALID.into()),
        };
        clause.push_str(&format!(" AND {column}=?3"));
        params.push(param);
    }
    let total = scalar(
        db,
        &format!("SELECT count(*) FROM identity_scim_resources WHERE {clause}"),
        &params,
    )
    .await?;
    ensure!((0..=25000).contains(&total), "SCIM source limit exceeded");
    let mut page = Vec::new();
    if query.count > 0 && query.start_index <= total as usize {
        let limit = params.len() + 1;
        params.push((query.count as i64).into());
        params.push((query.start_index.saturating_sub(1) as i64).into());
        let rows=db.query(&format!("SELECT kind,member_count,record FROM identity_scim_resources WHERE {clause} ORDER BY id LIMIT ?{limit} OFFSET ?{}",limit+1),&params).await?;
        for row in rows {
            page.push(hydrate(db, source, &row).await?);
        }
    }
    Ok(Reply::List(query.response(total as usize, &page)?))
}
fn reserved(resource: &Resource, source: &Source) -> Result<i64> {
    Ok(
        (resource.storage_base(source)?.len() + resource.data().members().len() * EDGE_BYTES)
            as i64,
    )
}
async fn counters(
    db: &mut impl Database,
    source: &Source,
    stage: &Stage,
    deltas: [i64; 4],
    now: i64,
) -> Result<()> {
    let old = [
        stage.users,
        stage.groups,
        stage.memberships,
        stage.reserved_bytes,
    ];
    let max = [20000, 5000, 100000, MAX_BYTES];
    let mut next = [0i64; 4];
    for i in 0..4 {
        next[i] = (old[i] as i64).checked_add(deltas[i]).ok_or(scim::LIMIT)?;
        if !(0..=max[i] as i64).contains(&next[i]) {
            return Err(scim::LIMIT.into());
        }
    }
    let revision = stage.revision.next()?;
    let changed=db.execute("UPDATE identity_scim_sources SET sequence=?2,users=?3,groups=?4,memberships=?5,reserved_bytes=?6,modified=?7 WHERE source_id=?1 AND sequence=?8",&[source.id.as_str().into(),(revision.sequence as i64).into(),next[0].into(),next[1].into(),next[2].into(),next[3].into(),now.into(),(stage.revision.sequence as i64).into()]).await?;
    ensure!(
        changed == 1,
        "SCIM source revision changed inside transaction"
    );
    Ok(())
}
async fn put(
    db: &mut impl Database,
    source: &Source,
    stage: &Stage,
    old: Option<&Resource>,
    next: &Resource,
    now: i64,
) -> Result<()> {
    if old == Some(next) {
        return Ok(());
    }
    if let Some(login)=next.data().user_name_key() && scalar(db,"SELECT count(*) FROM identity_scim_resources WHERE source_id=?1 AND user_name_key=?2 AND id<>?3",&[source.id.as_str().into(),login.into(),next.id().into()]).await?>0 {return Err(CONFLICT.into());}
    // Verify references in a single bounded query before writing. FK triples
    // enforce source+kind again when edges are inserted.
    if !next.data().members().is_empty() {
        let mut params = vec![source.id.as_str().into()];
        let mut expected = BTreeMap::new();
        for member in next.data().members() {
            let (id, kind) = edge(member);
            if id == next.id() || expected.insert(id, kind).is_some() {
                return Err(scim::INVALID.into());
            }
            params.push(id.into());
        }
        let placeholders = (2..=params.len())
            .map(|i| format!("?{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let rows=db.query(&format!("SELECT id,kind FROM identity_scim_resources WHERE source_id=?1 AND id IN ({placeholders})"),&params).await?;
        if rows.len() != expected.len()
            || rows
                .iter()
                .any(|r| r.text(0).ok().and_then(|id| expected.get(id).copied()) != r.text(1).ok())
        {
            return Err(scim::INVALID.into());
        }
    }
    let base = next.storage_base(source)?;
    let data = next.data();
    let delta_members =
        data.members().len() as i64 - old.map_or(0, |r| r.data().members().len()) as i64;
    let delta_bytes =
        reserved(next, source)? - old.map(|r| reserved(r, source)).transpose()?.unwrap_or(0);
    counters(
        db,
        source,
        stage,
        [
            i64::from(old.is_none() && data.kind() == ResourceType::User),
            i64::from(old.is_none() && data.kind() == ResourceType::Group),
            delta_members,
            delta_bytes,
        ],
        now,
    )
    .await?;
    db.execute("INSERT INTO identity_scim_resources(source_id,id,kind,user_name_key,external_id,display_name_key,active,member_count,record) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT(source_id,id) DO UPDATE SET user_name_key=excluded.user_name_key,external_id=excluded.external_id,display_name_key=excluded.display_name_key,active=excluded.active,member_count=excluded.member_count,record=excluded.record",&[source.id.as_str().into(),next.id().into(),data.kind().name().into(),text(data.user_name_key()),text(data.external_id.clone()),text(data.display_name.as_ref().map(|s|s.to_lowercase())),Param::Integer(data.active.map(i64::from)),(data.members().len() as i64).into(),base.into()]).await?;
    let empty = BTreeSet::new();
    memberships(
        db,
        source,
        next.id(),
        old.map_or(&empty, |r| r.data().members()),
        data.members(),
    )
    .await?;
    Ok(())
}
/// Keep unchanged edges in place. A display-name change must not rewrite all
/// memberships, and a full group replacement must not require4096 round trips.
async fn memberships(
    db: &mut impl Database,
    source: &Source,
    group: &str,
    previous: &BTreeSet<Member>,
    next: &BTreeSet<Member>,
) -> Result<()> {
    const BATCH: usize = 128;
    let removed: Vec<_> = previous.difference(next).collect();
    for chunk in removed.chunks(BATCH) {
        let mut params = vec![source.id.as_str().into(), group.into()];
        params.extend(chunk.iter().map(|m| edge(m).0.into()));
        let placeholders = (3..=params.len())
            .map(|i| format!("?{i}"))
            .collect::<Vec<_>>()
            .join(",");
        let changed = db.execute(
            &format!("DELETE FROM identity_scim_members WHERE source_id=?1 AND group_id=?2 AND member_id IN ({placeholders})"),
            &params,
        ).await?;
        ensure!(changed == chunk.len() as u64, "SCIM membership disappeared");
    }
    let added: Vec<_> = next.difference(previous).collect();
    for chunk in added.chunks(BATCH) {
        let mut params = vec![source.id.as_str().into(), group.into()];
        let mut tuples = Vec::with_capacity(chunk.len());
        for member in chunk {
            let (id, kind) = edge(member);
            let index = params.len() + 1;
            tuples.push(format!("(?1,?2,?{index},?{})", index + 1));
            params.push(id.into());
            params.push(kind.into());
        }
        let changed = db.execute(
            &format!("INSERT INTO identity_scim_members(source_id,group_id,member_id,member_kind) VALUES {}",tuples.join(",")),
            &params,
        ).await?;
        ensure!(
            changed == chunk.len() as u64,
            "SCIM membership insert incomplete"
        );
    }
    Ok(())
}

async fn delete(
    db: &mut impl Database,
    source: &Source,
    stage: &Stage,
    old: &Resource,
    now: i64,
) -> Result<()> {
    let rows=db.query("SELECT r.kind,r.member_count,r.record FROM identity_scim_resources r JOIN identity_scim_members m ON m.source_id=r.source_id AND m.group_id=r.id WHERE m.source_id=?1 AND m.member_id=?2 ORDER BY r.id LIMIT 5001",&[source.id.as_str().into(),old.id().into()]).await?;
    ensure!(rows.len() <= 5000, "SCIM group limit exceeded");
    let incoming = rows.len() as i64;
    let mut delta_bytes = -reserved(old, source)?;
    for row in rows {
        let group = base(&row, source)?;
        ensure!(row.integer(1)? > 0, "Invalid referencing SCIM group");
        let next = group.membership_removed(now)?;
        let raw = next.storage_base(source)?;
        delta_bytes += raw.len() as i64 - row.text(2)?.len() as i64 - EDGE_BYTES as i64;
        let changed=db.execute("UPDATE identity_scim_resources SET record=?3,member_count=member_count-1 WHERE source_id=?1 AND id=?2 AND kind='Group' AND member_count>0",&[source.id.as_str().into(),group.id().into(),raw.into()]).await?;
        ensure!(changed == 1, "SCIM referencing group disappeared");
    }
    db.execute(
        "DELETE FROM identity_scim_members WHERE source_id=?1 AND (group_id=?2 OR member_id=?2)",
        &[source.id.as_str().into(), old.id().into()],
    )
    .await?;
    let changed = db
        .execute(
            "DELETE FROM identity_scim_resources WHERE source_id=?1 AND id=?2",
            &[source.id.as_str().into(), old.id().into()],
        )
        .await?;
    ensure!(changed == 1, "SCIM resource disappeared");
    counters(
        db,
        source,
        stage,
        [
            -i64::from(old.data().kind() == ResourceType::User),
            -i64::from(old.data().kind() == ResourceType::Group),
            -incoming - old.data().members().len() as i64,
            delta_bytes,
        ],
        now,
    )
    .await?;
    Ok(())
}
pub(crate) async fn inventory(
    db: &mut impl Database,
    record: &Record,
    now: i64,
) -> Result<Inventory> {
    let stage = stage(db, record, now).await?;
    let source = record.metadata.source.clone();
    let rows=db.query("SELECT kind,member_count,record FROM identity_scim_resources WHERE source_id=?1 ORDER BY id LIMIT 25001",&[source.id.as_str().into()]).await?;
    ensure!(
        rows.len() == stage.users + stage.groups && rows.len() <= 25000,
        "SCIM inventory counts changed"
    );
    let edges=db.query("SELECT group_id,member_id,member_kind FROM identity_scim_members WHERE source_id=?1 ORDER BY group_id,member_id LIMIT 100001",&[source.id.as_str().into()]).await?;
    ensure!(
        edges.len() == stage.memberships && edges.len() <= 100000,
        "SCIM membership counts changed"
    );
    let mut grouped: BTreeMap<String, BTreeSet<Member>> = BTreeMap::new();
    for edge in edges {
        grouped
            .entry(edge.text(0)?.into())
            .or_default()
            .insert(parse_edge(&edge, 1, 2)?);
    }
    let mut resources = Vec::with_capacity(rows.len());
    let mut bytes = 0usize;
    let mut users = 0;
    for row in rows {
        bytes = bytes
            .checked_add(row.text(2)?.len())
            .context("SCIM inventory byte overflow")?;
        ensure!(bytes <= MAX_BYTES, "SCIM inventory too large");
        let base = base(&row, &source)?;
        let members = grouped.remove(base.id()).unwrap_or_default();
        ensure!(
            members.len() as i64 == row.integer(1)?,
            "SCIM group count changed"
        );
        users += usize::from(base.data().kind() == ResourceType::User);
        resources.push(base.with_stored_members(&source, members)?);
    }
    ensure!(
        grouped.is_empty()
            && users == stage.users
            && bytes + stage.memberships * EDGE_BYTES == stage.reserved_bytes,
        "Inconsistent SCIM inventory accounting"
    );
    Ok(Inventory {
        source,
        stage,
        resources,
    })
}
