use super::*;
use crate::config::Mode;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Dns {
    calls: AtomicUsize,
    answer: Answer,
    delay: Duration,
}
impl Resolver for Dns {
    async fn lookup(&self, _: &str) -> Answer {
        self.calls.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(self.delay).await;
        self.answer.clone()
    }
}
fn zone(id: &str, provider: &str) -> Zone {
    Zone {
        list: List {
            enabled: true,
            id: id.into(),
            provider: provider.into(),
            zone: format!("{id}.example.test"),
            key_env: None,
            listed_codes: vec!["127.0.0.2".parse().unwrap()],
            observe_codes: vec!["127.0.0.10".parse().unwrap()],
            ipv6: true,
        },
        suffix: format!("{id}.example.test"),
        dqs: false,
    }
}
fn runtime(codes: &[&str]) -> Runtime<Dns> {
    Runtime {
        settings: Settings {
            action: Action::Reject,
            ..Default::default()
        },
        zones: vec![zone("one", "first"), zone("two", "second")],
        resolver: Dns {
            calls: AtomicUsize::new(0),
            answer: Answer {
                codes: Ok(codes.iter().map(|c| c.parse().unwrap()).collect()),
                ttl: Duration::from_secs(60),
            },
            delay: Duration::ZERO,
        },
        slots: Capacity::new(8),
        cache: Mutex::new(HashMap::new()),
    }
}
const IP: &str = "8.8.8.8";

#[tokio::test]
async fn independent_consensus_observation_and_cache_are_distinct() {
    let r = runtime(&["127.0.0.2"]);
    for mode in [Mode::Observe, Mode::Tag, Mode::Enforce] {
        let report = r.check(IP.parse().unwrap(), mode, true).await;
        assert!(report.would_block);
        assert_eq!(report.listed_providers, 2);
        assert_eq!(
            report.effective_action,
            if mode == Mode::Enforce {
                Action::Reject
            } else {
                Action::Observe
            }
        );
        assert_eq!(report.smtp_reply().is_some(), mode == Mode::Enforce);
    }
    assert_eq!(r.resolver.calls.load(Ordering::SeqCst), 2);
    let mut r = runtime(&["127.0.0.2"]);
    r.zones[1].list.provider = "first".into();
    assert!(
        !r.check(IP.parse().unwrap(), Mode::Enforce, true)
            .await
            .would_block
    );
    r.settings.minimum_providers = 1;
    r.settings.action = Action::Defer;
    assert!(
        r.check(IP.parse().unwrap(), Mode::Enforce, true)
            .await
            .smtp_reply()
            .unwrap()
            .starts_with("451 ")
    );
}

#[tokio::test]
async fn unknown_mixed_error_and_policy_answers_never_block() {
    for codes in [
        vec![],
        vec!["127.0.0.10"],
        vec!["127.255.255.254"],
        vec!["127.0.0.2", "127.255.255.250"],
        vec!["192.0.2.1"],
        vec!["127.0.0.99"],
    ] {
        let r = runtime(&codes);
        let report = r.check(IP.parse().unwrap(), Mode::Enforce, true).await;
        assert!(!report.would_block, "{codes:?}");
        assert!(report.smtp_reply().is_none());
        if report.checks[0].status == Status::Unavailable {
            assert!(report.checks[0].codes.is_empty());
        }
    }
    let mut r = runtime(&["127.0.0.2"]);
    r.zones[0].dqs = true;
    r.zones[1].dqs = true;
    for code in ["127.0.0.10", "127.0.0.11", "127.0.0.30"] {
        r.resolver.answer.codes = Ok(vec![code.parse().unwrap()]);
        r.cache.lock().unwrap().clear();
        let report = r.check(IP.parse().unwrap(), Mode::Enforce, true).await;
        assert!(report.checks.iter().all(|c| c.status == Status::Policy));
        assert!(!report.would_block);
    }
    assert!(
        r.check(IP.parse().unwrap(), Mode::Enforce, false)
            .await
            .checks
            .is_empty()
    );
}

#[tokio::test]
async fn deadlines_busy_partial_results_and_cancellation_fail_open() {
    let mut r = runtime(&["127.0.0.2"]);
    r.settings.timeout_ms = 10;
    r.resolver.delay = Duration::from_secs(60);
    let start = Instant::now();
    let report = r.check(IP.parse().unwrap(), Mode::Enforce, true).await;
    assert!(start.elapsed() < Duration::from_secs(1));
    assert!(
        report
            .checks
            .iter()
            .all(|c| c.incident == Some(Incident::Timeout))
    );
    assert!(!report.would_block);
    assert_eq!(r.slots.available_permits(), 8);
    assert!(r.cache.lock().unwrap().is_empty());
    let r = runtime(&["127.0.0.2"]);
    let _held = (0..8)
        .map(|_| r.slots.try_acquire().unwrap())
        .collect::<Vec<_>>();
    assert!(
        r.check(IP.parse().unwrap(), Mode::Enforce, true)
            .await
            .checks
            .iter()
            .all(|c| c.incident == Some(Incident::Busy))
    );
    assert_eq!(r.resolver.calls.load(Ordering::SeqCst), 0);
    drop(_held);
    r.check(IP.parse().unwrap(), Mode::Observe, true).await;
    // Positive cache remains useful when no query slots are available.
    let _held = (0..8)
        .map(|_| r.slots.try_acquire().unwrap())
        .collect::<Vec<_>>();
    let report = r.check(IP.parse().unwrap(), Mode::Observe, true).await;
    assert!(
        report
            .checks
            .iter()
            .all(|c| c.cached && c.status == Status::Listed)
    );
    // One cached positive is insufficient when another provider is unavailable.
    r.cache.lock().unwrap().remove("8.8.8.8.two.example.test.");
    let report = r.check(IP.parse().unwrap(), Mode::Enforce, true).await;
    assert!(
        report
            .checks
            .iter()
            .any(|c| c.incident == Some(Incident::Busy))
    );
    assert!(report.smtp_reply().is_none());
}

#[tokio::test]
async fn cache_respects_zero_negative_ttl_expiry_and_capacity() {
    let mut r = runtime(&[]);
    r.resolver.answer.ttl = Duration::ZERO;
    r.check(IP.parse().unwrap(), Mode::Observe, true).await;
    r.check(IP.parse().unwrap(), Mode::Observe, true).await;
    assert_eq!(r.resolver.calls.load(Ordering::SeqCst), 4);
    assert!(r.cache.lock().unwrap().is_empty());
    r.settings.cache_entries = 2;
    r.resolver.answer.ttl = Duration::from_millis(10);
    r.check(IP.parse().unwrap(), Mode::Observe, true).await;
    assert!(
        r.check(IP.parse().unwrap(), Mode::Observe, true)
            .await
            .checks
            .iter()
            .all(|c| c.cached)
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        r.check(IP.parse().unwrap(), Mode::Observe, true)
            .await
            .checks
            .iter()
            .all(|c| !c.cached)
    );
    for ip in ["1.1.1.1", "9.9.9.9", "8.8.4.4"] {
        r.check(ip.parse().unwrap(), Mode::Observe, true).await;
    }
    assert!(r.cache.lock().unwrap().len() <= 2);
}

#[tokio::test]
async fn only_public_socket_ips_ipv4_mapped_and_nibble_ipv6_are_queried() {
    let r = runtime(&[]);
    for ip in [
        "127.0.0.1",
        "10.0.0.1",
        "192.0.2.1",
        "::1",
        "::ffff:127.0.0.1",
        "fe80::1",
        "2001:db8::1",
    ] {
        assert!(
            r.check(ip.parse().unwrap(), Mode::Enforce, true)
                .await
                .checks
                .iter()
                .all(|c| c.status == Status::Skipped)
        );
    }
    assert_eq!(r.resolver.calls.load(Ordering::SeqCst), 0);
    assert_eq!(reverse("::ffff:1.2.3.4".parse().unwrap()), "4.3.2.1");
    let ipv6 = reverse("2001:4860:4860::8888".parse().unwrap());
    assert_eq!(ipv6.split('.').count(), 32);
    assert!(ipv6.starts_with("8.8.8.8.0.0."));
    assert!(ipv6.ends_with("0.6.8.4.1.0.0.2"));
    let mut r = runtime(&[]);
    r.zones[0].list.ipv6 = false;
    let report = r
        .check("2001:4860:4860::8888".parse().unwrap(), Mode::Observe, true)
        .await;
    assert_eq!(report.checks[0].status, Status::Skipped);
    assert_eq!(report.checks[1].status, Status::NotListed);
}

#[test]
fn config_rejects_dangerous_or_ambiguous_lists() {
    let mut settings = Settings {
        lists: vec![zone("one", "first").list],
        ..Default::default()
    };
    settings.validate().unwrap();
    for code in ["192.0.2.1", "127.255.255.254"] {
        settings.lists[0].listed_codes = vec![code.parse().unwrap()];
        assert!(settings.validate().is_err());
    }
    settings.lists[0] = zone("one", "first").list;
    settings.lists.push(settings.lists[0].clone());
    assert!(settings.validate().is_err());
    settings.lists.pop();
    for zone in [
        "zen.spamhaus.org",
        "dbl.spamhaus.org",
        "key.zen.dq.spamhaus.net",
        "example.test\r\nInjected",
    ] {
        settings.lists[0].zone = zone.into();
        assert!(settings.validate().is_err());
    }
}

#[test]
fn persisted_report_has_no_query_secret_and_does_not_change_classification() {
    let mut r = runtime(&["127.0.0.2"]);
    r.zones[0].suffix = "private-test-credential.one.example.test".into();
    let mut scan = crate::engine::Scan {
        score: 42.0,
        complete: true,
        ..Default::default()
    };
    let report = Report {
        version: VERSION.into(),
        elapsed_ms: 1,
        checks: vec![Check {
            id: "one".into(),
            provider: "first".into(),
            status: Status::Listed,
            codes: vec!["127.0.0.2".parse().unwrap()],
            incident: None,
            cached: false,
        }],
        listed_providers: 1,
        minimum_providers: 2,
        would_block: false,
        requested_action: Action::Observe,
        effective_action: Action::Observe,
    };
    report.attach(&mut scan);
    assert_eq!(scan.score, 42.0);
    assert!(scan.complete);
    assert!(scan.reasons.is_empty());
    let json = serde_json::to_string(&scan).unwrap();
    assert!(!json.contains("private-test-credential"));
    assert_eq!(
        serde_json::from_str::<crate::engine::Scan>(&json)
            .unwrap()
            .early_rbl
            .unwrap()
            .listed_providers,
        1
    );
}

/// Local DNS authority, including NXDOMAIN, NODATA and provider errors. Never external DNS.
pub(crate) async fn dns_fixture() -> (Runtime, tokio::task::JoinHandle<()>) {
    use mail_auth::hickory_resolver::{
        config::{NameServerConfig, ResolverConfig, ResolverOpts},
        proto::{
            op::{Message, OpCode},
            rr::{
                Name, Record,
                rdata::{A, SOA},
            },
        },
    };
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut buffer = [0; 4096];
        loop {
            let (n, peer) = socket.recv_from(&mut buffer).await.unwrap();
            let request = Message::from_vec(&buffer[..n]).unwrap();
            let query = request.queries[0].clone();
            let mut response = Message::response(request.id, OpCode::Query);
            response.metadata.authoritative = true;
            response.metadata.recursion_available = true;
            response.metadata.recursion_desired = request.recursion_desired;
            response.add_query(query.clone());
            let name = query.name().to_ascii();
            if name.contains("nx.") || name.contains("empty.") {
                if name.contains("nx.") {
                    response.metadata.response_code = ResponseCode::NXDomain;
                }
                response.add_authority(Record::from_rdata(
                    Name::from_ascii("example.test.").unwrap(),
                    30,
                    RData::SOA(SOA::new(
                        Name::from_ascii("ns.example.test.").unwrap(),
                        Name::from_ascii("hostmaster.example.test.").unwrap(),
                        1,
                        60,
                        60,
                        60,
                        30,
                    )),
                ));
            } else if name.contains("fail.") {
                response.metadata.response_code = ResponseCode::ServFail;
            } else {
                let code = if name.contains("error.") {
                    "127.255.255.254"
                } else {
                    "127.0.0.2"
                };
                response.add_answer(Record::from_rdata(
                    query.name().clone(),
                    60,
                    RData::A(A(code.parse().unwrap())),
                ));
            }
            socket
                .send_to(&response.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let mut ns = NameServerConfig::udp(addr.ip());
    ns.connections[0].port = addr.port();
    let mut opts = ResolverOpts::default();
    opts.attempts = 1;
    opts.timeout = Duration::from_millis(100);
    opts.cache_size = 0;
    let r = Runtime {
        settings: Settings {
            action: Action::Reject,
            ..Default::default()
        },
        zones: vec![zone("one", "first"), zone("two", "second")],
        resolver: SystemDns(
            MessageAuthenticator::new(ResolverConfig::from_name_servers(vec![ns]), opts).unwrap(),
        ),
        slots: Capacity::new(8),
        cache: Mutex::new(HashMap::new()),
    };
    (r, task)
}

#[tokio::test]
async fn actual_dns_adapter_distinguishes_negative_error_and_valid_answers() {
    let (r, task) = dns_fixture().await;
    let report = r.check(IP.parse().unwrap(), Mode::Enforce, true).await;
    assert_eq!(report.listed_providers, 2);
    assert!(report.would_block);
    for (name, status) in [
        ("nx.example.test.", Status::NotListed),
        ("empty.example.test.", Status::Unavailable),
        ("fail.example.test.", Status::Unavailable),
        ("error.example.test.", Status::Unavailable),
    ] {
        let answer = r.resolver.lookup(name).await;
        let found = interpret(&r.zones[0], &answer)
            .map(|(s, _)| s)
            .unwrap_or(Status::Unavailable);
        assert_eq!(found, status, "{name}");
        if found == Status::NotListed {
            assert!(answer.ttl > Duration::ZERO && answer.ttl <= Duration::from_secs(30));
        }
    }
    task.abort();
    let _ = task.await;
}
