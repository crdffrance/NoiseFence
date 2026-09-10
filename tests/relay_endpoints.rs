use noisefence::config::{Config, endpoint, valid_address, valid_domain};

#[test]
fn mx_root_dot_is_canonicalized_without_relaxing_endpoint_validation() {
    for route in ["gmail-smtp-in.l.google.com", "gmail-smtp-in.l.google.com."] {
        assert_eq!(
            endpoint(route, 25),
            Some(("gmail-smtp-in.l.google.com", 25))
        );
        assert_eq!(
            endpoint(&format!("{route}:2525"), 25),
            Some(("gmail-smtp-in.l.google.com", 2525))
        );
    }
    for invalid in [
        ".",
        "..",
        "mx..",
        ".mx",
        "mx..example",
        "mx.example..:25",
        "mx.example.:0",
        "mx.example.:65536",
        "mx.example.:",
        "mx.example.:25:25",
        "mx.example.\r\n",
        " mx.example.",
        "user@mx.example.",
        "[::1]:25",
        "mx_example.",
    ] {
        assert!(endpoint(invalid, 25).is_none(), "accepted {invalid:?}");
    }
    assert!(endpoint("mx.example.", 0).is_none());
    let longest = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(longest.len(), 253);
    assert_eq!(
        endpoint(&format!("{longest}."), 25),
        Some((longest.as_str(), 25))
    );
    assert!(endpoint(&format!("{longest}e."), 25).is_none());
    assert!(!valid_domain("example.test."));
    assert!(!valid_address("alice@example.test."));
}

#[test]
fn rooted_routes_cannot_bypass_gateway_loop_checks() {
    let root = tempfile::tempdir().unwrap();
    let mut config: Config = toml::from_str(include_str!("../config/development.toml")).unwrap();
    config.data_dir = root.path().into();
    for route in [
        format!("{}.", config.hostname),
        format!("{}.:25", config.hostname.to_uppercase()),
        format!("{}.", config.domains[0].name),
        format!("{}.:2525", config.domains[0].name.to_uppercase()),
    ] {
        config.domains[0].next_hops = vec![route.clone()];
        assert!(config.validate().is_err(), "accepted loop {route}");
    }
    config.domains[0].next_hops = vec!["mail.protonmail.ch.:25".into()];
    config.validate().unwrap();
}
