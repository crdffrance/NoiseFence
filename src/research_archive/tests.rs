use super::*;
fn context(id: &str, now: i64) -> ContextRecord {
    ContextRecord {
        format: 1,
        id: id.into(),
        created: now,
        expires: 0,
        hostname: "mx.example.com".into(),
        build: env!("CARGO_PKG_VERSION").into(),
        peer_ip: "192.0.2.10".into(),
        helo: "sender.example".into(),
        sender: "sender@example.com".into(),
        recipients: vec!["hidden@example.org".into()],
        encrypted_transport: true,
        raw_sha256: String::new(),
        configuration_sha256: "0".repeat(64),
        message_ids: vec![id.into()],
        observations: vec![serde_json::json!({"score":99.6})],
        observations_updated_at: now,
        observations_final: true,
    }
}
fn runtime(root: &Path) -> Runtime {
    let r = Runtime::new(root);
    r.configure(Settings {
        enabled: true,
        collect_until: crate::now() + 86400,
        ..Default::default()
    });
    r
}
#[test]
fn deadline_is_absolute_and_bounded() {
    let mut s = Settings::default();
    assert!(!s.collecting(crate::now()));
    s.enabled = true;
    assert!(s.validate().is_err());
    s.collect_until = crate::now() + 60;
    assert!(s.validate().is_ok());
    assert!(s.collecting(s.collect_until - 1));
    assert!(!s.collecting(s.collect_until));
    s.collect_until = crate::now() + 91 * 86400;
    assert!(s.validate().is_err());
    s.collect_until = 1;
    assert!(s.validate().is_ok());
    assert!(!s.collecting(crate::now()));
}
#[test]
fn ciphertext_authenticates_context_and_preserves_exact_original() {
    let tmp = tempfile::tempdir().unwrap();
    let r = runtime(tmp.path());
    let id = uuid::Uuid::new_v4().to_string();
    let raw = b"Subject: private\r\n\r\nDo not lose my bytes.\r\n";
    r.persist(raw.to_vec(), context(&id, crate::now()), 0)
        .unwrap();
    let folder = r.root.join("objects").join(&id);
    let data = fs::read(folder.join("message.enc")).unwrap();
    assert!(!data.windows(7).any(|s| s == b"private"));
    let k = key(&r.root, false).unwrap();
    assert!(read_sealed(&folder.join("message.enc"), &k, "different-context", 1024).is_err());
    let out = tmp.path().join("export");
    r.export(&id, &out).unwrap();
    assert_eq!(fs::read(out.join("message.eml")).unwrap(), raw);
    assert!(r.export(&id, &out).is_err());
    assert_eq!(out.metadata().unwrap().permissions().mode() & 0o077, 0);
    let mut broken = data;
    let i = broken.len() - 1;
    broken[i] ^= 1;
    fs::write(folder.join("message.enc"), broken).unwrap();
    assert!(r.export(&id, &tmp.path().join("broken")).is_err());
    assert!(!tmp.path().join("broken").exists());
}
#[test]
fn expiry_purges_even_when_collection_disabled_and_export_refuses_expired() {
    let tmp = tempfile::tempdir().unwrap();
    let r = runtime(tmp.path());
    let id = uuid::Uuid::new_v4().to_string();
    r.persist(b"mail".to_vec(), context(&id, crate::now() - 31 * 86400), 0)
        .unwrap();
    r.configure(Settings::default());
    assert!(r.export(&id, &tmp.path().join("expired")).is_err());
    let mut db = r.database().unwrap();
    r.purge_expired(&mut db, crate::now()).unwrap();
    assert!(!r.root.join("objects").join(id).exists());
    assert_eq!(r.status().unwrap().messages, 0);
}
#[test]
fn reserve_and_mixed_domain_scope_fail_open_without_plaintext() {
    let tmp = tempfile::tempdir().unwrap();
    let r = runtime(tmp.path());
    let id = uuid::Uuid::new_v4().to_string();
    r.persist(b"mail".to_vec(), context(&id, crate::now()), u64::MAX)
        .unwrap();
    assert_eq!(r.status().unwrap().messages, 0);
    assert_eq!(r.status().unwrap().counters["disk_reserve"], 1);
    r.configure(Settings {
        enabled: true,
        collect_until: crate::now() + 3600,
        domains: vec!["example.com".into()],
        ..Default::default()
    });
    r.persist(b"mail".to_vec(), context(&id, crate::now()), 0)
        .unwrap();
    assert_eq!(r.status().unwrap().messages, 0);
    assert_eq!(r.status().unwrap().counters["domain_scope"], 1);
}
#[test]
fn stopped_policy_cancels_queued_capture_and_original_is_never_truncated() {
    let tmp = tempfile::tempdir().unwrap();
    let r = runtime(tmp.path());
    r.configure(Settings {
        enabled: true,
        collect_until: 1,
        ..Default::default()
    });
    let id = uuid::Uuid::new_v4().to_string();
    r.persist(vec![b'x'; 2048], context(&id, crate::now()), 0)
        .unwrap();
    assert!(!r.root.exists());
    r.configure(Settings {
        enabled: true,
        collect_until: crate::now() + 30,
        max_message_bytes: 1024,
        ..Default::default()
    });
    r.persist(vec![b'x'; 2048], context(&id, crate::now()), 0)
        .unwrap();
    assert!(!r.root.exists());
    assert_eq!(r.status().unwrap().counters["oversize"], 1);
}
#[tokio::test]
async fn final_observations_survive_delivery_cleanup_and_archive_is_not_a_queue() {
    let tmp = tempfile::tempdir().unwrap();
    let store = crate::store::Store::open(tmp.path()).unwrap();
    store.archive.configure(Settings {
        enabled: true,
        collect_until: crate::now() + 3600,
        ..Default::default()
    });
    let id = uuid::Uuid::new_v4().to_string();
    let mut c = context(&id, crate::now());
    c.observations_final = false;
    c.observations = vec![serde_json::json!({"rspamd":{"status":"pending"}})];
    store.archive.persist(b"original".to_vec(), c, 0).unwrap();
    let key = id.clone();
    store
        .run(move |db| {
            db.execute(
                "INSERT INTO messages(id,created,sender,scan,raw_present) VALUES(?1,?2,'',?3,0)",
                params![
                    key,
                    crate::now(),
                    r#"{"score":2.5,"rspamd":{"status":"complete","score":-0.1}}"#
                ],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    store.archive.maintain(&store).await.unwrap();
    store.cleanup().await.unwrap();
    let out = tmp.path().join("export");
    store.archive.export(&id, &out).unwrap();
    let c: ContextRecord =
        serde_json::from_slice(&fs::read(out.join("context.json")).unwrap()).unwrap();
    assert!(c.observations_final);
    assert_eq!(c.observations[0]["rspamd"]["score"], -0.1);
    assert_eq!(fs::read(out.join("message.eml")).unwrap(), b"original");
}

#[test]
fn quota_skips_new_originals_and_never_evicts_existing_examples() {
    let tmp = tempfile::tempdir().unwrap();
    let r = runtime(tmp.path());
    r.configure(Settings {
        enabled: true,
        collect_until: crate::now() + 3600,
        quota_mib: 64,
        ..Default::default()
    });
    for _ in 0..3 {
        let id = uuid::Uuid::new_v4().to_string();
        r.persist(vec![b'x'; 25 * 1024 * 1024], context(&id, crate::now()), 0)
            .unwrap();
    }
    let s = r.status().unwrap();
    assert_eq!(s.messages, 2);
    assert_eq!(s.counters["quota_full"], 1);
    assert!(s.stored_bytes <= 64 * MIB);
    assert_eq!(fs::read_dir(r.root.join("objects")).unwrap().count(), 2);
}
#[tokio::test]
async fn startup_repairs_quota_accounting_and_removes_interrupted_ciphertext_writes() {
    let tmp = tempfile::tempdir().unwrap();
    let store = crate::store::Store::open(tmp.path()).unwrap();
    let r = &store.archive;
    r.configure(Settings {
        enabled: true,
        collect_until: crate::now() + 3600,
        ..Default::default()
    });
    let id = uuid::Uuid::new_v4().to_string();
    r.persist(b"mail".to_vec(), context(&id, crate::now()), 0)
        .unwrap();
    let expected = r.status().unwrap().stored_bytes;
    r.database()
        .unwrap()
        .execute("UPDATE entries SET stored_bytes=0", [])
        .unwrap();
    let interrupted = r
        .root
        .join("objects")
        .join(&id)
        .join(format!(".write-{}", uuid::Uuid::new_v4()));
    fs::write(&interrupted, b"unfinished ciphertext").unwrap();
    r.maintain(&store).await.unwrap();
    assert_eq!(r.status().unwrap().stored_bytes, expected);
    assert!(!interrupted.exists());
    assert_eq!(r.status().unwrap().messages, 1);
}
#[tokio::test]
async fn missing_key_is_not_silently_replaced_and_empty_expired_archive_loses_its_key() {
    let tmp = tempfile::tempdir().unwrap();
    let store = crate::store::Store::open(tmp.path()).unwrap();
    let r = &store.archive;
    r.configure(Settings {
        enabled: true,
        collect_until: crate::now() + 3600,
        ..Default::default()
    });
    let id = uuid::Uuid::new_v4().to_string();
    r.persist(b"mail".to_vec(), context(&id, crate::now() - 31 * 86400), 0)
        .unwrap();
    assert!(r.root.join("archive.key").exists());
    r.configure(Settings::default());
    r.maintain(&store).await.unwrap();
    assert!(!r.root.join("archive.key").exists());
    r.configure(Settings {
        enabled: true,
        collect_until: crate::now() + 3600,
        ..Default::default()
    });
    let id = uuid::Uuid::new_v4().to_string();
    r.persist(b"mail".to_vec(), context(&id, crate::now()), 0)
        .unwrap();
    fs::remove_file(r.root.join("archive.key")).unwrap();
    let next = uuid::Uuid::new_v4().to_string();
    assert!(
        r.persist(b"new".to_vec(), context(&next, crate::now()), 0)
            .is_err()
    );
    assert!(!r.root.join("archive.key").exists());
}
