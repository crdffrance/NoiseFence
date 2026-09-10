use super::*;
use axum::{
    body::Body,
    http::{Request, Response},
    routing::any,
};
use std::sync::{Arc, Mutex};

#[tokio::test]
async fn real_dns_adapter_checks_both_families_and_rejects_partial_failure() {
    use mail_auth::hickory_resolver::{
        config::{NameServerConfig, ResolverConfig, ResolverOpts},
        proto::{
            op::{Message, OpCode},
            rr::{
                Record,
                rdata::{A, AAAA},
            },
        },
    };
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        loop {
            let (n, peer) = socket.recv_from(&mut bytes).await.unwrap();
            let request = Message::from_vec(&bytes[..n]).unwrap();
            let q = request.queries[0].clone();
            let name = q.name().to_ascii();
            let mut answer = Message::response(request.id, OpCode::Query);
            answer.metadata.recursion_available = true;
            answer.metadata.authoritative = true;
            answer.add_query(q.clone());
            let record = match (name.as_str(), q.query_type()) {
                ("missing.example.org.", _) => {
                    answer.metadata.response_code = ResponseCode::NXDomain;
                    None
                }
                ("partial.example.org.", RecordType::AAAA) => {
                    answer.metadata.response_code = ResponseCode::ServFail;
                    None
                }
                (_, RecordType::A) => Some(RData::A(A("8.8.8.8".parse().unwrap()))),
                ("mixed.example.org.", RecordType::AAAA) => {
                    Some(RData::AAAA(AAAA("fd00::1".parse().unwrap())))
                }
                (_, RecordType::AAAA) => {
                    Some(RData::AAAA(AAAA("2001:4860:4860::8888".parse().unwrap())))
                }
                _ => panic!("unexpected query"),
            };
            if let Some(record) = record {
                answer.add_answer(Record::from_rdata(q.name().clone(), 0, record));
            }
            socket
                .send_to(&answer.to_vec().unwrap(), peer)
                .await
                .unwrap();
        }
    });
    let mut ns = NameServerConfig::udp(address.ip());
    ns.connections[0].port = address.port();
    let mut options = ResolverOpts::default();
    options.attempts = 1;
    options.timeout = Duration::from_millis(100);
    let mut resolver = Resolver::new(Settings::default()).unwrap();
    resolver.dns =
        MessageAuthenticator::new(ResolverConfig::from_name_servers(vec![ns]), options).unwrap();
    let addresses = resolver.addresses("public.example.org").await.unwrap();
    assert_eq!(addresses.len(), 2);
    assert!(addresses.into_iter().all(public_ip));
    let addresses = resolver.addresses("mixed.example.org").await.unwrap();
    assert!(addresses.iter().any(|ip| !public_ip(*ip)));
    assert_eq!(
        resolver.addresses("partial.example.org").await.unwrap_err(),
        Detail::Dns
    );
    assert_eq!(
        resolver.addresses("missing.example.org").await.unwrap_err(),
        Detail::Dns
    );
    server.abort();
}

type Routes = Vec<(
    &'static str,
    u16,
    Vec<(&'static str, &'static str)>,
    &'static str,
)>;
async fn fixture(
    routes: Routes,
) -> (
    Resolver,
    Arc<Mutex<Vec<Request<Body>>>>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let captured = Arc::new(Mutex::new(vec![]));
    let requests = captured.clone();
    let app = axum::Router::new().fallback(any(move |request: Request<Body>| {
        let route = routes.iter().find(|r| r.0 == request.uri().path()).cloned();
        requests.lock().unwrap().push(request);
        async move {
            let (_, code, headers, body) = route.expect("unexpected synthetic request");
            let mut response = Response::builder().status(code);
            for (name, value) in headers {
                response = response.header(name, value);
            }
            response.body(Body::from(body)).unwrap()
        }
    }));
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let mut resolver = Resolver::new(Settings {
        timeout_ms: 1500,
        ..Default::default()
    })
    .unwrap();
    resolver.test_peer = Some(address);
    for host in [
        "start.example.com",
        "landing.example.org",
        "mixed.example.com",
        "blocked.example.com",
    ] {
        resolver
            .test_dns
            .lock()
            .unwrap()
            .insert(host.into(), vec!["8.8.8.8".parse().unwrap()]);
    }
    (resolver, captured, task)
}

#[test]
fn addresses_protocols_credentials_and_ports_are_conservative() {
    assert_eq!(report_site("8.8.8.8"), "[adresse IP]");
    assert_eq!(report_site("[2606:4700:4700::1111]"), "[adresse IP]");
    assert_eq!(report_site("private-token.example.com."), "example.com");
    for ip in [
        "0.0.0.0",
        "10.0.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "100.100.100.200",
        "172.31.1.1",
        "192.168.0.1",
        "192.0.2.1",
        "198.19.0.1",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "::ffff:127.0.0.1",
        "fc00::1",
        "fe80::1",
        "ff02::1",
        "64:ff9b::7f00:1",
        "64:ff9b:1::1",
        "2002:7f00:1::1",
        "2001:db8::1",
        "2001::1",
        "2001:20::1",
        "3fff::1",
    ] {
        assert!(!public_ip(ip.parse().unwrap()), "{ip}");
    }
    for ip in [
        "1.1.1.1",
        "8.8.8.8",
        "2606:4700:4700::1111",
        "2001:4860:4860::8888",
    ] {
        assert!(public_ip(ip.parse().unwrap()));
    }
    for url in [
        "file:///etc/passwd",
        "gopher://example.com",
        "http://localhost/",
        "http://a.local/",
        "http://example.com:25/",
        "https://example.com:80/",
        "http://alice:secret@example.com/",
        "http://example.com/\n",
        "http://example.com\\@127.0.0.1",
        "http://[fe80::1%25eth0]/",
    ] {
        assert!(safe_url(url).is_err(), "{url}");
    }
    let url = safe_url("https://EXAMPLE.com:443/a?q=secret#fragment").unwrap();
    assert_eq!(url.as_str(), "https://example.com/a?q=secret");
    assert!(
        local_addresses()
            .unwrap()
            .contains(&"127.0.0.1".parse().unwrap())
    );
}

#[tokio::test]
async fn real_http_relative_meta_and_base_redirects_preserve_requests_but_redact_reports() {
    let (resolver, captured, server) = fixture(vec![
        ("/start", 302, vec![("location", "/middle?private_token=CANARY"), ("set-cookie", "identity=PRIVATE")], ""),
        ("/middle", 200, vec![("content-type", "text/html")], "<base href='http://landing.example.org/root/'><meta http-equiv='Refresh' content='0; URL=final?secret=CANARY&amp;x=1'>"),
        ("/root/final", 200, vec![("content-type", "text/html")], "<p>final</p>"),
    ]).await;
    let (report, urls) = resolver
        .inspect(&["http://start.example.com/start".into()], false)
        .await;
    let chain = &report.chains[0];
    assert!(chain.complete, "{chain:?}");
    assert_eq!(chain.hops.len(), 3);
    assert_eq!(chain.hops[2].site, "example.org");
    assert!(urls.contains("http://landing.example.org/root/final?secret=CANARY&x=1"));
    let json = serde_json::to_string(&report).unwrap();
    for private in [
        "CANARY",
        "private_token",
        "/middle",
        "start.example.com",
        "identity",
    ] {
        assert!(!json.contains(private));
    }
    for request in captured.lock().unwrap().iter() {
        assert_eq!(request.method(), "GET");
        for header in ["cookie", "authorization", "referer", "x-api-key"] {
            assert!(!request.headers().contains_key(header));
        }
        assert!(
            request.headers()["host"]
                .to_str()
                .unwrap()
                .contains("example")
        );
    }
    server.abort();
}

#[tokio::test]
async fn every_redirect_is_checked_before_connecting_even_with_mixed_dns_answers() {
    for location in [
        "http://127.1/private",
        "http://2130706433/private",
        "http://[::ffff:127.0.0.1]/private",
        "http://169.254.169.254/latest/meta-data/",
        "http://mixed.example.com/next",
        "http://blocked.example.com/next",
    ] {
        let location: &'static str = location;
        let (mut resolver, captured, server) =
            fixture(vec![("/", 302, vec![("location", location)], "")]).await;
        resolver.test_dns.lock().unwrap().insert(
            "mixed.example.com".into(),
            vec!["8.8.8.8".parse().unwrap(), "10.0.0.1".parse().unwrap()],
        );
        resolver
            .settings
            .blocked_ips
            .push("9.9.9.9".parse().unwrap());
        resolver.test_dns.lock().unwrap().insert(
            "blocked.example.com".into(),
            vec!["9.9.9.9".parse().unwrap()],
        );
        let (report, _) = resolver
            .inspect(&["http://start.example.com/".into()], false)
            .await;
        assert_eq!(
            report.chains[0].detail,
            Some(Detail::ForbiddenAddress),
            "{location}: {report:?}"
        );
        assert_eq!(captured.lock().unwrap().len(), 1);
        server.abort();
    }
}

#[tokio::test]
async fn loops_hop_limit_ambiguous_headers_scripts_and_body_limits_remain_incomplete() {
    for (routes, detail, hops) in [
        (
            vec![("/", 302, vec![("location", "/")], "")],
            Detail::Loop,
            1,
        ),
        (
            vec![
                ("/", 302, vec![("location", "/a")], ""),
                ("/a", 308, vec![("location", "/b")], ""),
            ],
            Detail::HopLimit,
            2,
        ),
        (
            vec![("/", 302, vec![("location", "/a"), ("location", "/b")], "")],
            Detail::InvalidRedirect,
            1,
        ),
        (
            vec![(
                "/",
                200,
                vec![("refresh", "0;url=/a"), ("refresh", "0;url=/b")],
                "",
            )],
            Detail::InvalidRedirect,
            1,
        ),
        (
            vec![(
                "/",
                200,
                vec![("content-type", "text/html")],
                Box::leak("x".repeat(65537).into_boxed_str()),
            )],
            Detail::BodyLimit,
            1,
        ),
        (
            vec![(
                "/",
                200,
                vec![("content-type", "text/html")],
                "<script>location='/secret'</script>",
            )],
            Detail::ClientScript,
            1,
        ),
        (
            vec![(
                "/",
                200,
                vec![("content-type", "text/html"), ("content-encoding", "gzip")],
                "opaque",
            )],
            Detail::Encoding,
            1,
        ),
        (vec![("/", 503, vec![], "")], Detail::HttpStatus, 1),
    ] {
        let (mut resolver, captured, server) = fixture(routes).await;
        resolver.settings.max_redirects = 1;
        let (report, _) = resolver
            .inspect(&["http://start.example.com/".into()], false)
            .await;
        assert_eq!(report.chains[0].detail, Some(detail));
        assert!(!report.chains[0].complete);
        assert_eq!(captured.lock().unwrap().len(), hops);
        server.abort();
    }
}

#[tokio::test]
async fn total_deadline_busy_and_cancellation_never_leave_background_fetches() {
    use tokio::io::AsyncReadExt;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut resolver = Resolver::new(Settings {
        timeout_ms: 100,
        max_parallel: 1,
        ..Default::default()
    })
    .unwrap();
    resolver.test_peer = Some(listener.local_addr().unwrap());
    resolver
        .test_dns
        .lock()
        .unwrap()
        .insert("start.example.com".into(), vec!["8.8.8.8".parse().unwrap()]);
    let close = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = vec![];
        socket.read_to_end(&mut bytes).await.unwrap();
    });
    let urls = vec!["http://start.example.com/".into()];
    let permit = resolver.slots.acquire().await.unwrap();
    assert_eq!(
        resolver.inspect(&urls, false).await.0.chains[0].detail,
        Some(Detail::Busy)
    );
    drop(permit);
    let (report, _) = resolver.inspect(&urls, false).await;
    assert_eq!(report.chains[0].detail, Some(Detail::Deadline));
    tokio::time::timeout(Duration::from_secs(2), close)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resolver.slots.available_permits(), 1);
}

#[test]
fn html_is_inert_bounded_and_resolves_entities_without_fetching_subresources() {
    let base = safe_url("https://example.com/a/").unwrap();
    assert_eq!(html_next(&base,"<!-- <meta http-equiv=refresh content='0;url=/evil'> --><img src='http://127.0.0.1/'><form action='/danger'></form>").unwrap(), None);
    assert_eq!(
        html_next(
            &base,
            "<meta http-equiv=refresh content='0;URL=../b?x=1&amp;y=2'>"
        )
        .unwrap()
        .unwrap()
        .as_str(),
        "https://example.com/b?x=1&y=2"
    );
    assert_eq!(
        html_next(&base, &"<script></script>".repeat(1025)).unwrap_err(),
        Detail::BodyLimit
    );
    assert!(refresh_target("NaN;url=/x").is_err());
    assert!(refresh_target("0;url=").unwrap().is_empty());
}

#[tokio::test]
async fn live_protection_checks_final_exact_url_and_offline_processing_does_not_fetch() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("protection")).unwrap();
    std::fs::write(root.path().join("protection/url-feed.json"), serde_json::json!({"version":1,"updated":crate::now(),"urls":["http://landing.example.org/final?token=CANARY"]}).to_string()).unwrap();
    let (resolver, captured, server) = fixture(vec![
        (
            "/",
            302,
            vec![("location", "http://landing.example.org/final?token=CANARY")],
            "",
        ),
        ("/final", 200, vec![("content-type", "text/html")], "final"),
    ])
    .await;
    let mut config: crate::config::Config =
        toml::from_str(include_str!("../../../config/development.toml")).unwrap();
    config.data_dir = root.path().into();
    let mut settings = crate::protection::Settings::default();
    settings.policy.follow_urls = true;
    settings.policy.campaigns = false;
    config.protection = Some(settings.clone());
    let mut runtime = crate::protection::Runtime::new(&settings, root.path()).unwrap();
    runtime.redirects = resolver;
    let raw = b"From: sender@example.com\r\nContent-Type: text/html\r\n\r\n<a href='http://start.example.com/'>Open</a><form action='http://start.example.com/do-not-submit'></form>";
    let (report, targets) = runtime.local(raw, "", &config);
    assert_eq!(targets.urls.len(), 1);
    assert!(captured.lock().unwrap().is_empty());
    let mut scan = crate::engine::Scan {
        protection: Some(report),
        ..Default::default()
    };
    let mut disabled = settings.policy.clone();
    disabled.follow_urls = false;
    runtime
        .observe(&mut scan, super::super::Targets::default(), &disabled, &[])
        .await;
    assert!(scan.protection.as_ref().unwrap().url_resolution.is_none());
    assert!(captured.lock().unwrap().is_empty());
    runtime
        .observe(&mut scan, targets, &settings.policy, &[])
        .await;
    let report = scan.protection.unwrap();
    assert!(report.url_resolution.unwrap().chains[0].complete);
    assert!(
        report
            .findings
            .iter()
            .any(|f| f.id == "known_phishing_url" && f.sources.contains(&"redirect".into()))
    );
    assert!(
        !serde_json::to_string(&report.findings)
            .unwrap()
            .contains("CANARY")
    );
    assert_eq!(captured.lock().unwrap().len(), 2);
    server.abort();
}

#[tokio::test]
async fn dns_is_revalidated_on_a_same_host_redirect() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut resolver = Resolver::new(Settings::default()).unwrap();
    resolver.test_peer = Some(listener.local_addr().unwrap());
    resolver
        .test_dns
        .lock()
        .unwrap()
        .insert("start.example.com".into(), vec!["8.8.8.8".parse().unwrap()]);
    let resolver = Arc::new(resolver);
    let changed = resolver.clone();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = vec![];
        while !request.ends_with(b"\r\n\r\n") {
            request.push(socket.read_u8().await.unwrap());
        }
        changed.test_dns.lock().unwrap().insert(
            "start.example.com".into(),
            vec!["127.0.0.1".parse().unwrap()],
        );
        socket.write_all(b"HTTP/1.1 302 Found\r\nLocation: /private\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
    });
    let (report, _) = resolver
        .inspect(&["http://start.example.com/".into()], false)
        .await;
    assert_eq!(report.chains[0].detail, Some(Detail::ForbiddenAddress));
    assert_eq!(report.chains[0].hops.len(), 1);
    server.await.unwrap();
}

#[tokio::test]
async fn untrusted_tls_certificate_is_rejected_before_http() {
    let (mut resolver, _, unused) = fixture(vec![]).await;
    unused.abort();
    let key = rcgen::generate_simple_self_signed(vec!["start.example.com".into()]).unwrap();
    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![key.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()).into(),
        )
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    resolver.test_peer = Some(listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        assert!(
            tokio_rustls::TlsAcceptor::from(Arc::new(tls))
                .accept(socket)
                .await
                .is_err()
        );
    });
    let (report, urls) = resolver
        .inspect(&["https://start.example.com/".into()], false)
        .await;
    assert_eq!(report.chains[0].detail, Some(Detail::Network));
    assert!(report.chains[0].hops.is_empty());
    assert!(urls.is_empty());
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn url_budget_and_legacy_configuration_remain_explicit() {
    let (mut resolver, captured, server) = fixture(vec![("/", 200, vec![], "")]).await;
    resolver.settings.max_urls = 1;
    let (report, _) = resolver
        .inspect(
            &[
                "http://start.example.com/".into(),
                "http://landing.example.org/".into(),
            ],
            true,
        )
        .await;
    assert_eq!(report.omitted, 2);
    assert_eq!(report.chains.len(), 1);
    assert_eq!(captured.lock().unwrap().len(), 1);
    let policy: crate::protection::Policy = serde_json::from_str("{}").unwrap();
    assert!(!policy.follow_urls);
    let mut old = serde_json::to_value(crate::protection::Report::default()).unwrap();
    old.as_object_mut().unwrap().remove("url_resolution");
    old["crdf"].as_object_mut().unwrap().remove("omitted");
    let old: crate::protection::Report = serde_json::from_value(old).unwrap();
    assert!(old.url_resolution.is_none());
    assert_eq!(old.crdf.omitted, 0);
    server.abort();
}
