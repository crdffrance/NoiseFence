#[allow(dead_code)] // Other integration suites also use the shared message fixture.
mod common;
use noisefence::config::{Config, Domain};
use std::collections::BTreeMap;

fn pilot(config: &mut Config) {
    config.domains.push(Domain {
        name: "pilot.example.test".into(),
        next_hops: vec![],
        recipients: vec![],
        aliases: BTreeMap::from([(
            "probe@pilot.example.test".into(),
            "alice@example.test".into(),
        )]),
    });
}

#[test]
fn explicit_cross_domain_alias_uses_the_canonical_destination_route() {
    let root = tempfile::tempdir().unwrap();
    let mut config = (*common::config(root.path())).clone();
    pilot(&mut config);
    config.validate().unwrap();
    let alias = config.recipient("probe@PILOT.EXAMPLE.TEST").unwrap();
    assert_eq!(alias.address, "probe@pilot.example.test");
    assert_eq!(alias.destination, "alice@example.test");
    assert_eq!(alias.hosts, config.domains[0].next_hops);
    // The alias domain must never redirect a canonical mailbox via its own route.
    config.domains[1].next_hops = vec!["unused-route.example.org".into()];
    config.validate().unwrap();
    assert_eq!(
        config.recipient("probe@pilot.example.test").unwrap().hosts,
        alias.hosts
    );
    for unknown in [
        "alice@pilot.example.test",
        "unknown@pilot.example.test",
        "victim@external.test",
        "Probe@pilot.example.test",
    ] {
        assert!(config.recipient(unknown).is_none(), "accepted {unknown}");
    }
    let input = include_str!("../config/development.toml").to_string()
        + "\n[[domains]]\nname=\"pilot.example.test\"\nrecipients=[]\n[domains.aliases]\n\"probe@pilot.example.test\"=\"alice@example.test\"\n";
    let parsed: Config = toml::from_str(&input).unwrap();
    parsed.validate().unwrap();
    assert_eq!(
        parsed
            .recipient("probe@pilot.example.test")
            .unwrap()
            .destination,
        alias.destination
    );
}

#[test]
fn aliases_cannot_chain_loop_escape_the_allowlist_or_hide_ambiguous_addresses() {
    let root = tempfile::tempdir().unwrap();
    let mut good = (*common::config(root.path())).clone();
    pilot(&mut good);
    for target in [
        "victim@external.test",
        "missing@example.test",
        "billing@example.test",
        "probe@pilot.example.test",
        "alice@example.test\r\nRCPT TO:<x@elsewhere.test>",
    ] {
        let mut config = good.clone();
        config.domains[1]
            .aliases
            .insert("probe@pilot.example.test".into(), target.into());
        assert!(config.validate().is_err(), "accepted {target:?}");
        assert!(config.recipient("probe@pilot.example.test").is_none());
    }
    let mut cycle = good.clone();
    cycle.domains[0].aliases.insert(
        "billing@example.test".into(),
        "probe@pilot.example.test".into(),
    );
    cycle.domains[1].aliases.insert(
        "probe@pilot.example.test".into(),
        "billing@example.test".into(),
    );
    assert!(cycle.validate().is_err());
    assert!(cycle.recipient("probe@pilot.example.test").is_none());
    let mut duplicate = good.clone();
    duplicate.domains[1]
        .aliases
        .insert("probe@PILOT.EXAMPLE.TEST".into(), "bob@example.test".into());
    assert!(duplicate.validate().is_err());
    let mut shadowed = good.clone();
    shadowed.domains[0]
        .aliases
        .insert("alice@EXAMPLE.TEST".into(), "bob@example.test".into());
    assert!(shadowed.validate().is_err());
    let mut duplicate_recipient = good.clone();
    duplicate_recipient.domains[0]
        .recipients
        .push("alice@EXAMPLE.TEST".into());
    assert!(duplicate_recipient.validate().is_err());
    good.domains[0].next_hops.clear();
    assert!(good.validate().is_err());
}

#[test]
fn domain_case_is_insensitive_but_local_parts_and_acl_destinations_are_preserved() {
    let root = tempfile::tempdir().unwrap();
    let mut config = (*common::config(root.path())).clone();
    config.domains[0].name = "EXAMPLE.TEST".into();
    config.domains[0]
        .recipients
        .push("Alice@Example.Test".into());
    pilot(&mut config);
    config.domains[1].aliases.insert(
        "probe@pilot.example.test".into(),
        "Alice@EXAMPLE.TEST".into(),
    );
    config.domains[1].aliases.insert(
        "\"Quoted Key\"@pilot.example.test".into(),
        "alice@example.test".into(),
    );
    config.validate().unwrap();
    assert_eq!(
        config.recipient("alice@EXAMPLE.TEST").unwrap().destination,
        "alice@example.test"
    );
    assert_eq!(
        config.recipient("Alice@example.test").unwrap().destination,
        "Alice@Example.Test"
    );
    assert_eq!(
        config
            .recipient("probe@PILOT.EXAMPLE.TEST")
            .unwrap()
            .destination,
        "Alice@Example.Test"
    );
    assert_eq!(
        config
            .recipient("\"Quoted Key\"@PILOT.EXAMPLE.TEST")
            .unwrap()
            .destination,
        "alice@example.test"
    );
    assert!(config.recipient("ALICE@example.test").is_none());
    assert!(
        config
            .recipient("\"quoted key\"@pilot.example.test")
            .is_none()
    );
}
