use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[tokio::test]
async fn system_dns_adapter_distinguishes_nxdomain_nodata_servfail_and_record_types() {
    use mail_auth::hickory_resolver::{
        config::{NameServerConfig, ResolverConfig, ResolverOpts},
        proto::{
            op::{Message, OpCode},
            rr::{
                Record as DnsRecord,
                rdata::{A, AAAA, MX, PTR, SOA},
            },
        },
    };
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
            let request = Message::from_vec(&buf[..n]).unwrap();
            let query = request.queries[0].clone();
            let mut reply = Message::response(request.id, OpCode::Query);
            reply.metadata.recursion_desired = request.recursion_desired;
            reply.metadata.recursion_available = true;
            reply.metadata.authoritative = true;
            reply.add_query(query.clone());
            let name = query.name().to_ascii().to_ascii_lowercase();
            let data = if name == "nx.example.org." || name == "empty.example.org." {
                if name.starts_with("nx.") {
                    reply.metadata.response_code = ResponseCode::NXDomain;
                }
                reply.add_authority(DnsRecord::from_rdata(
                    Name::from_ascii("example.org.").unwrap(),
                    30,
                    RData::SOA(SOA::new(
                        Name::from_ascii("ns.example.org.").unwrap(),
                        Name::from_ascii("hostmaster.example.org.").unwrap(),
                        1,
                        60,
                        60,
                        60,
                        30,
                    )),
                ));
                None
            } else if name == "fail.example.org." {
                reply.metadata.response_code = ResponseCode::ServFail;
                None
            } else {
                Some(match query.query_type() {
                    RecordType::A => RData::A(A("192.0.2.1".parse().unwrap())),
                    RecordType::AAAA => RData::AAAA(AAAA("2001:db8::1".parse().unwrap())),
                    RecordType::MX => RData::MX(MX::new(0, Name::root())),
                    RecordType::PTR => {
                        RData::PTR(PTR(Name::from_ascii("outbound.example.org.").unwrap()))
                    }
                    other => panic!("unexpected query type {other:?}"),
                })
            };
            if let Some(data) = data {
                reply.add_answer(DnsRecord::from_rdata(query.name().clone(), 60, data));
            }
            socket
                .send_to(&reply.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let mut nameserver = NameServerConfig::udp(addr.ip());
    nameserver.connections[0].port = addr.port();
    let mut options = ResolverOpts::default();
    options.attempts = 1;
    options.timeout = Duration::from_millis(200);
    options.cache_size = 0;
    let dns = SystemDns(
        MessageAuthenticator::new(ResolverConfig::from_name_servers(vec![nameserver]), options)
            .unwrap(),
    );
    let cases = [
        (
            Query::A("outbound.example.org".into()),
            Record::Ip("192.0.2.1".parse().unwrap()),
        ),
        (
            Query::Aaaa("outbound.example.org".into()),
            Record::Ip("2001:db8::1".parse().unwrap()),
        ),
        (Query::Mx("example.org".into()), Record::Mx(0, ".".into())),
        (
            Query::Ptr("192.0.2.1".parse().unwrap()),
            Record::Host("outbound.example.org.".into()),
        ),
        (
            Query::Ptr("2001:db8::1".parse().unwrap()),
            Record::Host("outbound.example.org.".into()),
        ),
    ];
    for (query, expected) in cases {
        let answer = tokio::time::timeout(Duration::from_secs(2), dns.lookup(&query))
            .await
            .unwrap();
        assert_eq!(answer.records.unwrap(), vec![expected]);
        assert!(answer.ttl > Duration::ZERO && answer.ttl <= Duration::from_secs(60));
    }
    for name in ["nx.example.org", "empty.example.org"] {
        let answer = dns.lookup(&Query::Mx(name.into())).await;
        assert_eq!(answer.records.unwrap(), vec![]);
        assert!(answer.ttl > Duration::ZERO && answer.ttl <= Duration::from_secs(30));
    }
    let answer = dns.lookup(&Query::Mx("fail.example.org".into())).await;
    assert!(answer.records.is_err());
    server.abort();
    let _ = server.await;
}

#[derive(Default)]
struct Dns {
    answers: HashMap<Query, Answer>,
    calls: AtomicUsize,
}
impl Dns {
    fn set(&mut self, query: Query, records: Vec<Record>) {
        self.answers.insert(
            query,
            Answer {
                records: Ok(records),
                ttl: Duration::from_secs(60),
            },
        );
    }
    fn addresses(&mut self, host: &str, ips: &[&str]) {
        let ips: Vec<IpAddr> = ips.iter().map(|ip| ip.parse().unwrap()).collect();
        self.set(
            Query::A(host.into()),
            ips.iter()
                .filter(|ip| ip.is_ipv4())
                .copied()
                .map(Record::Ip)
                .collect(),
        );
        self.set(
            Query::Aaaa(host.into()),
            ips.iter()
                .filter(|ip| ip.is_ipv6())
                .copied()
                .map(Record::Ip)
                .collect(),
        );
    }
}
impl Resolver for Dns {
    async fn lookup(&self, query: &Query) -> Answer {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.answers
            .get(query)
            .unwrap_or_else(|| panic!("unexpected DNS query: {query:?}"))
            .clone()
    }
}
fn setup(ip: &str) -> (IpAddr, Dns) {
    let peer = ip.parse().unwrap();
    let mut dns = Dns::default();
    dns.addresses("outbound.example.org", &[ip]);
    dns.set(
        Query::Ptr(peer),
        vec![Record::Host("outbound.example.org.".into())],
    );
    // A different inbound host is normal and must not trigger a mismatch.
    dns.set(
        Query::Mx("example.org".into()),
        vec![Record::Mx(10, "inbound.other.example.".into())],
    );
    (peer, dns)
}
fn scoring() -> PolicyConfig {
    PolicyConfig {
        contribute_to_score: true,
        ..Default::default()
    }
}
fn has(result: &PolicyResult, id: &str) -> bool {
    result.checks.iter().any(|r| r.id == id)
}

#[tokio::test]
async fn verified_ipv4_ipv6_cache_and_no_requirement_to_send_from_inbound_mx() {
    for ip in ["192.0.2.1", "2001:db8::1"] {
        let (peer, dns) = setup(ip);
        let policy = Policy::with_resolver(scoring(), dns);
        let result = policy
            .check(
                peer,
                "OUTBOUND.Example.Org.",
                "sender@example.org",
                "gateway.example.org",
            )
            .await;
        assert_eq!(result.status, PolicyStatus::Complete);
        assert_eq!(result.applied_weight, -0.25);
        assert!(
            has(&result, "helo_verified")
                && has(&result, "ptr_verified")
                && has(&result, "sender_mx_present")
        );
        let calls = policy.resolver.calls.load(Ordering::SeqCst);
        let repeat = policy
            .check(
                peer,
                "outbound.example.org",
                "another@example.org",
                "gateway.example.org",
            )
            .await;
        assert_eq!(repeat.applied_weight, result.applied_weight);
        assert_eq!(policy.resolver.calls.load(Ordering::SeqCst), calls);
        // Cache expiry must not preserve an earlier trusted identity.
        for (expires, _) in policy.cache.lock().unwrap().values_mut() {
            *expires = Instant::now();
        }
        policy
            .check(
                peer,
                "outbound.example.org",
                "sender@example.org",
                "gateway.example.org",
            )
            .await;
        assert!(policy.resolver.calls.load(Ordering::SeqCst) > calls);
    }
}

#[tokio::test]
async fn null_sender_valid_literals_and_multiple_ptr_names_are_supported() {
    for (ip, helo) in [
        ("192.0.2.1", "[192.0.2.1]"),
        ("2001:db8::1", "[IPv6:2001:db8::1]"),
    ] {
        let (peer, mut dns) = setup(ip);
        dns.set(
            Query::Ptr(peer),
            vec![
                Record::Host("stale.example.org.".into()),
                Record::Host("outbound.example.org.".into()),
            ],
        );
        dns.addresses("stale.example.org", &["192.0.2.9"]);
        let result = Policy::with_resolver(scoring(), dns)
            .check(peer, helo, "", "gateway.example.org")
            .await;
        assert_eq!(result.status, PolicyStatus::Complete);
        assert!(
            has(&result, "sender_null")
                && has(&result, "ptr_verified")
                && has(&result, "helo_literal_match")
        );
        assert_eq!(result.applied_weight, -0.15);
    }
}

#[tokio::test]
async fn implicit_mx_accepts_ipv6_only_and_null_mx_is_distinct_from_dns_failure() {
    let (peer, mut dns) = setup("192.0.2.1");
    dns.set(Query::Mx("example.org".into()), vec![]);
    dns.addresses("example.org", &["2001:db8::9"]);
    let result = Policy::with_resolver(scoring(), dns)
        .check(
            peer,
            "outbound.example.org",
            "sender@example.org",
            "gateway.example.org",
        )
        .await;
    assert!(has(&result, "sender_implicit_mx"));
    assert_eq!(result.status, PolicyStatus::Complete);
    let (peer, mut dns) = setup("192.0.2.1");
    dns.set(
        Query::Mx("example.org".into()),
        vec![Record::Mx(0, ".".into())],
    );
    let result = Policy::with_resolver(scoring(), dns)
        .check(
            peer,
            "outbound.example.org",
            "sender@example.org",
            "gateway.example.org",
        )
        .await;
    assert!(has(&result, "sender_null_mx"));
    assert_eq!(result.status, PolicyStatus::Complete);
    assert!((result.applied_weight - 0.45).abs() < 1e-9);
}

#[tokio::test]
async fn unrelated_failures_are_capped_and_observation_does_not_change_the_content_score() {
    for apply in [false, true] {
        let (peer, mut dns) = setup("192.0.2.1");
        dns.set(
            Query::Ptr(peer),
            vec![Record::Host("unrelated.example.org.".into())],
        );
        dns.addresses("unrelated.example.org", &["192.0.2.2"]);
        dns.set(Query::Mx("example.org".into()), vec![]);
        dns.addresses("example.org", &[]);
        let config = PolicyConfig {
            contribute_to_score: apply,
            ..Default::default()
        };
        let result = Policy::with_resolver(config, dns)
            .check(
                peer,
                "gateway.example.org",
                "sender@example.org",
                "gateway.example.org",
            )
            .await;
        assert_eq!(result.status, PolicyStatus::Complete);
        assert_eq!(result.candidate_weight, 1.5);
        assert_eq!(result.applied_weight, if apply { 1.5 } else { 0.0 });
        assert!(
            has(&result, "helo_local_identity")
                && has(&result, "ptr_unconfirmed")
                && has(&result, "sender_no_mail_route")
        );
        let mut scan = crate::engine::Scan {
            complete: true,
            ..Default::default()
        };
        result.apply(&mut scan);
        assert_eq!(
            scan.reasons.iter().map(|s| s.weight).sum::<f64>(),
            result.applied_weight
        );
        assert!(scan.complete && !scan.tagged);
    }
}

#[tokio::test]
async fn missing_records_and_resolver_failure_have_different_outcomes() {
    for fail in [false, true] {
        let (peer, mut dns) = setup("192.0.2.1");
        dns.set(Query::Ptr(peer), vec![]);
        dns.addresses("outbound.example.org", &[]);
        if fail {
            dns.answers.insert(
                Query::Aaaa("outbound.example.org".into()),
                Answer::unavailable(),
            );
        }
        let result = Policy::with_resolver(scoring(), dns)
            .check(
                peer,
                "outbound.example.org",
                "sender@example.org",
                "gateway.example.org",
            )
            .await;
        let mut scan = crate::engine::Scan {
            complete: true,
            ..Default::default()
        };
        result.apply(&mut scan);
        if fail {
            assert_eq!(result.status, PolicyStatus::Unavailable);
            assert_eq!(result.applied_weight, 0.0);
            assert!(result.checks.is_empty());
            assert!(!scan.complete && !scan.tagged);
        } else {
            assert_eq!(result.status, PolicyStatus::Complete);
            assert!(has(&result, "ptr_missing") && has(&result, "helo_no_address"));
            assert_eq!(result.applied_weight, 0.75);
        }
    }
}

#[tokio::test]
async fn dns_limits_invalid_null_mx_and_unsafe_names_never_create_false_evidence() {
    let (peer, mut dns) = setup("192.0.2.1");
    dns.set(
        Query::Ptr(peer),
        vec![Record::Host("outbound.example.org.".into()); 5],
    );
    let result = Policy::with_resolver(scoring(), dns)
        .check(
            peer,
            "outbound.example.org",
            "sender@example.org",
            "gateway.example.org",
        )
        .await;
    assert_eq!(result.status, PolicyStatus::Unavailable);
    let (peer, mut dns) = setup("192.0.2.1");
    dns.set(
        Query::Mx("example.org".into()),
        vec![
            Record::Mx(0, ".".into()),
            Record::Mx(10, "mx.example.org.".into()),
        ],
    );
    let result = Policy::with_resolver(scoring(), dns)
        .check(
            peer,
            "outbound.example.org",
            "sender@example.org",
            "gateway.example.org",
        )
        .await;
    assert_eq!(result.status, PolicyStatus::Unavailable);
    for name in [
        "localhost",
        "[IPv6:bogus]",
        "192.0.2.1",
        "x.example\r\nInjected: yes",
        "*.example.org",
        "x.example.org..",
        "x..org",
        "é.example.org",
    ] {
        assert!(host(name).is_none());
    }
    assert!(literal("[2001:db8::1]").is_none());
}

struct Slow;
impl Resolver for Slow {
    async fn lookup(&self, _: &Query) -> Answer {
        std::future::pending().await
    }
}
#[tokio::test]
async fn bounded_deadline_and_busy_slots_fail_open_without_background_work() {
    let config = PolicyConfig {
        max_parallel: 1,
        timeout_ms: 20,
        ..Default::default()
    };
    let policy = Policy::with_resolver(config, Slow);
    let ip = "192.0.2.1".parse().unwrap();
    let check = || {
        policy.check(
            ip,
            "mail.example.org",
            "sender@example.org",
            "gateway.example.org",
        )
    };
    let (first, second) = tokio::join!(check(), check());
    assert_eq!(first.status, PolicyStatus::Unavailable);
    assert_eq!(second.status, PolicyStatus::Busy);
    assert!(first.elapsed_ms < 1000);
    assert_eq!(policy.slots.available_permits(), 1);
    assert!(policy.cache.lock().unwrap().is_empty());
}

#[tokio::test]
async fn cache_capacity_zero_ttl_and_errors_are_never_treated_as_clean_dns() {
    let (peer, mut dns) = setup("192.0.2.1");
    dns.answers.get_mut(&Query::Ptr(peer)).unwrap().ttl = Duration::ZERO;
    let policy = Policy::with_resolver(
        PolicyConfig {
            cache_entries: 1,
            ..Default::default()
        },
        dns,
    );
    policy.lookup(Query::Ptr(peer)).await.unwrap();
    policy.lookup(Query::Ptr(peer)).await.unwrap();
    assert_eq!(policy.resolver.calls.load(Ordering::SeqCst), 2);
    policy
        .lookup(Query::A("outbound.example.org".into()))
        .await
        .unwrap();
    policy
        .lookup(Query::Mx("example.org".into()))
        .await
        .unwrap();
    assert_eq!(policy.cache.lock().unwrap().len(), 1);
    let (peer, mut dns) = setup("192.0.2.1");
    dns.answers.insert(Query::Ptr(peer), Answer::unavailable());
    let policy = Policy::with_resolver(scoring(), dns);
    assert!(policy.lookup(Query::Ptr(peer)).await.is_err());
    assert!(policy.lookup(Query::Ptr(peer)).await.is_err());
    assert_eq!(policy.resolver.calls.load(Ordering::SeqCst), 1);
}

#[test]
fn configuration_defaults_bounds_and_legacy_scan() {
    let config: PolicyConfig = toml::from_str("").unwrap();
    assert!(!config.contribute_to_score);
    config.validate().unwrap();
    assert!(
        PolicyConfig {
            max_parallel: 0,
            ..config.clone()
        }
        .validate()
        .is_err()
    );
    assert!(
        PolicyConfig {
            timeout_ms: 5001,
            ..config.clone()
        }
        .validate()
        .is_err()
    );
    assert!(
        PolicyConfig {
            cache_entries: usize::MAX,
            ..config.clone()
        }
        .validate()
        .is_err()
    );
    assert!(
        PolicyConfig {
            cache_ttl_seconds: 0,
            ..config
        }
        .validate()
        .is_err()
    );
    assert!(toml::from_str::<PolicyConfig>("contribute_to_socre = true").is_err());
    let mut value = serde_json::to_value(crate::engine::Scan::default()).unwrap();
    value.as_object_mut().unwrap().remove("smtp_policy");
    let old: crate::engine::Scan = serde_json::from_value(value).unwrap();
    assert_eq!(old.smtp_policy.status, PolicyStatus::Disabled);
}
