use super::Status;
use rusqlite::{Connection, OpenFlags, params};
use std::{collections::HashSet, path::Path, time::Duration};

pub async fn inspect(
    root: &Path,
    enabled: bool,
    scopes: &[String],
    simhash: Option<&str>,
    fingerprint: &str,
    features: usize,
) -> (Status, bool, bool) {
    if !enabled {
        return (Status::Disabled, false, false);
    }
    // A shared Scan cannot disclose a campaign learned from another recipient's domain.
    if scopes.len() != 1 || features < 80 {
        return (Status::NotRun, false, false);
    }
    let Some(simhash) = simhash.and_then(|s| u64::from_str_radix(s, 16).ok()) else {
        return (Status::NotRun, false, false);
    };
    let path = root.join("state.sqlite3");
    let scope = format!("%@{}", scopes[0]);
    let fingerprint = fingerprint.to_owned();
    let (send, receive) = tokio::sync::oneshot::channel();
    let task = tokio::task::spawn_blocking(move || -> anyhow::Result<(bool, bool)> {
        let db = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        db.busy_timeout(Duration::from_millis(50))?;
        if send.send(db.get_interrupt_handle()).is_err() {
            return Ok((false, false));
        }
        let mut q=db.prepare("SELECT json_extract(m.scan,'$.campaign_simhash'),json_extract(m.scan,'$.fingerprint'),COALESCE(json_extract(m.scan,'$.raw_sha256'),m.id),MIN(f.spam),MAX(f.spam)
        FROM (SELECT id,scan FROM messages WHERE created>=?1 ORDER BY created DESC LIMIT 1000) m
        JOIN feedback f ON f.message_id=m.id AND f.created>=?1
        JOIN users u ON u.username=f.username AND u.admin=1 AND u.disabled=0
        WHERE EXISTS(SELECT 1 FROM deliveries d WHERE d.message_id=m.id AND lower(d.destination) LIKE ?2)
        AND json_array_length(m.scan,'$.features')>=80
        GROUP BY m.id")?;
        let rows = q.query_map(params![crate::now() - 30 * 86400, scope], |r| {
            Ok((
                r.get::<_, Option<String>>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, bool>(3)?,
                r.get::<_, bool>(4)?,
            ))
        })?;
        let mut spam = HashSet::new();
        let mut legitimate = false;
        for row in rows {
            let (similar, exact, hash, minimum, maximum) = row?;
            let near = similar
                .and_then(|s| u64::from_str_radix(&s, 16).ok())
                .is_some_and(|s| (s ^ simhash).count_ones() <= 2);
            if exact != fingerprint && !near {
                continue;
            }
            if !minimum {
                legitimate = true;
            }
            if maximum {
                spam.insert(hash);
            }
        }
        Ok((spam.len() >= 2, legitimate))
    });
    let work = async {
        struct Interrupt(Option<rusqlite::InterruptHandle>);
        impl Drop for Interrupt {
            fn drop(&mut self) {
                if let Some(handle) = &self.0 {
                    handle.interrupt();
                }
            }
        }
        let interrupt = Interrupt(receive.await.ok());
        let mut task = task;
        match tokio::time::timeout(Duration::from_millis(150), &mut task).await {
            Ok(Ok(Ok((matched, legit)))) => (Status::Complete, matched, legit),
            Ok(_) => (Status::Unavailable, false, false),
            Err(_) => {
                if let Some(interrupt) = &interrupt.0 {
                    interrupt.interrupt();
                }
                (Status::Limited, false, false)
            }
        }
    };
    // Connection opening is also bounded. A cancelled lookup must never create a finding.
    tokio::time::timeout(Duration::from_millis(250), work)
        .await
        .unwrap_or((Status::Limited, false, false))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn campaigns_require_current_admin_feedback_two_examples_and_matching_scope() {
        let root = tempfile::tempdir().unwrap();
        let store = crate::store::Store::open(root.path()).unwrap();
        store.run(|db|{
            db.execute("INSERT INTO users(username,password,admin) VALUES('reviewer','unused',1),('reader','unused',0)",[])?;
            for i in 0..3 {
                let id=format!("message-{i}");
                let raw=serde_json::json!({"campaign_simhash":"000000000000ffff","fingerprint":"campaign","raw_sha256":format!("hash-{i}"),"features":vec![(1,1);80]}).to_string();
                db.execute("INSERT INTO messages(id,created,sender,scan) VALUES(?1,?2,'sender',?3)",params![id,crate::now(),raw])?;
                db.execute("INSERT INTO deliveries(message_id,address,destination,hosts,next_attempt) VALUES(?1,'a@crdf.fr','a@crdf.fr','[]',0)",[&id])?;
                db.execute("INSERT INTO feedback(username,message_id,spam,created) VALUES(?1,?2,1,?3)",params![if i==2 {"reader"}else{"reviewer"},id,crate::now()])?;
            }Ok(())
        }).await.unwrap();
        let location = root.path();
        let check = |scopes: Vec<String>| async move {
            inspect(
                location,
                true,
                &scopes,
                Some("000000000000ffff"),
                "campaign",
                100,
            )
            .await
        };
        assert_eq!(
            check(vec!["crdf.fr".into()]).await,
            (Status::Complete, true, false)
        );
        assert_eq!(
            check(vec!["other.fr".into()]).await,
            (Status::Complete, false, false)
        );
        assert_eq!(
            check(vec!["crdf.fr".into(), "other.fr".into()]).await.0,
            Status::NotRun
        );
        store.run(|db|{db.execute("UPDATE feedback SET spam=0 WHERE username='reviewer' AND message_id='message-0'",[])?;Ok(())}).await.unwrap();
        assert_eq!(
            check(vec!["crdf.fr".into()]).await,
            (Status::Complete, false, true)
        );
        store
            .run(|db| {
                db.execute("UPDATE users SET disabled=1 WHERE username='reviewer'", [])?;
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(
            check(vec!["crdf.fr".into()]).await,
            (Status::Complete, false, false)
        );
    }
}
