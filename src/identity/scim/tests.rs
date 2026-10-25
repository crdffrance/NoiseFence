use super::*;
use crate::identity::directory::{Activity, Provider, Source};
use serde_json::{Value, json};
fn source() -> Source {
    Source {
        id: "scim-test".into(),
        label: "Test directory".into(),
        provider: Provider::Scim,
        authority: "fixture-org".into(),
        scopes: ["example.org".into()].into(),
        stale_after_seconds: 86400,
    }
}
fn user(name: &str) -> Value {
    json!({"schemas":[USER_SCHEMA],"userName":name,"displayName":"Émilie Example","emails":[{"value":"Emilie@example.org","type":"work","primary":true}]})
}
fn create(kind: ResourceType, value: Value) -> Resource {
    Resource::create(
        &source(),
        Data::parse(kind, &serde_json::to_vec(&value).unwrap()).unwrap(),
        1000,
    )
    .unwrap()
}
fn person() -> Resource {
    create(ResourceType::User, user("emilie@example.org"))
}
fn group(name: &str, members: Value) -> Resource {
    create(
        ResourceType::Group,
        json!({"schemas":[GROUP_SCHEMA],"displayName":name,"members":members}),
    )
}
fn patch(resource: &Resource, ops: Value) -> Result<Resource> {
    resource.patch(
        &serde_json::to_vec(&json!({"schemas":[PATCH_SCHEMA],"Operations":ops})).unwrap(),
        Some(&resource.etag()),
        1001,
    )
}
fn revision() -> Revision {
    Revision::new(&source(), uuid::Uuid::new_v4().to_string(), 1).unwrap()
}
fn candidate(rows: &[Resource]) -> Result<Candidate> {
    Candidate::prepare(source(), revision(), 1, rows, 1002, 1002)
}

#[test]
fn explicit_emails_only_and_unknown_activity() {
    let mut u = user("login@different.example");
    u.as_object_mut().unwrap().remove("emails");
    let row = create(ResourceType::User, u);
    let c = candidate(&[row]).unwrap();
    let p = &c.snapshot().people[0];
    assert!(p.addresses.is_empty());
    assert_eq!(p.activity, Activity::Unknown);
    assert!(p.protected_roles.is_empty());
    assert!(c.snapshot().delegations.is_empty());
}
#[test]
fn real_alias_local_case_is_preserved() {
    let mut u = user("example");
    u["emails"] = json!([{"value":"Emilie@EXAMPLE.ORG"},{"value":"emilie@example.org"}]);
    let c = candidate(&[create(ResourceType::User, u)]).unwrap();
    assert_eq!(c.snapshot().people[0].addresses.len(), 2);
    assert!(
        c.snapshot().people[0]
            .addresses
            .contains("Emilie@example.org")
    );
}
#[test]
fn active_never_follows_presence_or_login() {
    for (value, expected) in [
        (json!(true), Activity::Active),
        (json!(false), Activity::Inactive),
        (Value::Null, Activity::Unknown),
    ] {
        let mut u = user("employee");
        u["active"] = value;
        assert_eq!(create(ResourceType::User, u).data().activity(), expected);
    }
}
#[test]
fn input_attributes_are_case_insensitive() {
    let u = json!({"SCHEMAS":[USER_SCHEMA],"USERNAME":"employee","NAME":{"GIVENNAME":"Émilie","familyName":"Example"},"ACTIVE":true});
    let row = create(ResourceType::User, u);
    assert_eq!(row.document()["name"]["givenName"], "Émilie");
    assert_eq!(
        candidate(&[row]).unwrap().snapshot().people[0].display_name,
        "Émilie Example"
    );
}
#[test]
fn duplicate_attributes_fail_even_with_identical_spelling() {
    for input in [
        format!(r#"{{"schemas":["{USER_SCHEMA}"],"userName":"a","userName":"b"}}"#),
        format!(r#"{{"schemas":["{USER_SCHEMA}"],"userName":"a","USERNAME":"b"}}"#),
        format!(
            r#"{{"schemas":["{USER_SCHEMA}"],"userName":"a","name":{{"givenName":"A","GIVENNAME":"B"}}}}"#
        ),
    ] {
        assert_eq!(
            Data::parse(ResourceType::User, input.as_bytes()).unwrap_err(),
            SYNTAX
        );
    }
}
#[test]
fn unsupported_attributes_do_not_silently_grant_privileges() {
    for key in [
        "password",
        "roles",
        "protected_roles",
        "delegations",
        "entitlements",
        "groupsExtra",
    ] {
        let mut u = user("person");
        u[key] = json!(["administrator"]);
        assert!(Data::parse(ResourceType::User, &serde_json::to_vec(&u).unwrap()).is_err());
    }
}
#[test]
fn read_only_input_cannot_assign_ids_or_memberships() {
    let mut u = user("person");
    u["id"] = json!("attacker-id");
    u["meta"] = json!({"version":"attacker-version"});
    u["groups"] = json!([{"value":"finance"}]);
    let row = create(ResourceType::User, u);
    assert_ne!(row.id(), "attacker-id");
    assert!(!row.document().to_string().contains("attacker"));
    assert!(row.data().members().is_empty());
}
#[test]
fn unknown_extensions_and_bad_scalar_types_are_refused() {
    let mut u = user("person");
    u["schemas"] = json!([USER_SCHEMA, "urn:unknown"]);
    assert!(Data::parse(ResourceType::User, &serde_json::to_vec(&u).unwrap()).is_err());
    for value in [json!("false"), json!(0), json!([])] {
        let mut u = user("person");
        u["active"] = value;
        assert!(Data::parse(ResourceType::User, &serde_json::to_vec(&u).unwrap()).is_err());
    }
}
#[test]
fn international_names_are_not_mistaken_for_qualified_unicode_logins() {
    assert_eq!(person().data().label(), "Émilie Example");
    for name in ["émilie", "login name", "a\u{202e}b", "a\n"] {
        assert!(
            Data::parse(
                ResourceType::User,
                &serde_json::to_vec(&user(name)).unwrap()
            )
            .is_err()
        );
    }
}
#[test]
fn patch_is_atomic_on_late_failure() {
    let row = person();
    let before = row.encode(&source()).unwrap();
    assert!(patch(&row,json!([{"op":"replace","path":"displayName","value":"Changed"},{"op":"remove","path":"userName"}])).is_err());
    assert_eq!(row.encode(&source()).unwrap(), before);
}
#[test]
fn patch_order_and_case_are_supported() {
    let row = person();
    let changed=patch(&row,json!([{"OP":"RePlAcE","PATH":"active","VALUE":false},{"op":"replace","value":{"DISPLAYNAME":"New display"}},{"op":"add","path":"name.givenName","value":"Émilie"}])).unwrap();
    assert_eq!(changed.document()["active"], false);
    assert_eq!(changed.document()["displayName"], "New display");
    assert_eq!(changed.document()["name"]["givenName"], "Émilie");
    assert_ne!(changed.etag(), row.etag());
}
#[test]
fn qualified_paths_are_accepted_but_not_foreign_schemas() {
    let row = person();
    assert!(
        patch(
            &row,
            json!([{"op":"replace","path":format!("{USER_SCHEMA}:active"),"value":true}])
        )
        .is_ok()
    );
    assert!(
        patch(
            &row,
            json!([{"op":"replace","path":format!("{GROUP_SCHEMA}:active"),"value":true}])
        )
        .is_err()
    );
}
#[test]
fn optimistic_version_and_clock_guards() {
    let row = person();
    let b = serde_json::to_vec(&user("next")).unwrap();
    assert_eq!(
        row.replace(&b, Some("W/\"stale\""), 1001).unwrap_err(),
        STALE
    );
    assert!(row.replace(&b, None, 999).is_err());
    assert!(row.replace(&b, Some("*"), 1001).is_ok());
}
#[test]
fn replace_resets_optional_fields_but_preserves_server_identity() {
    let row = person();
    let next = row
        .replace(
            &serde_json::to_vec(&json!({"schemas":[USER_SCHEMA],"userName":"new"})).unwrap(),
            Some(&row.etag()),
            1001,
        )
        .unwrap();
    assert_eq!(row.id(), next.id());
    assert_eq!(
        row.document()["meta"]["created"],
        next.document()["meta"]["created"]
    );
    assert!(next.data().emails.is_empty());
    assert_eq!(next.data().activity(), Activity::Unknown);
}
#[test]
fn no_op_keeps_etag_and_timestamp() {
    let row = person();
    let next = row
        .replace(&serde_json::to_vec(&row.document()).unwrap(), None, 1001)
        .unwrap();
    assert_eq!(next, row);
    let again = patch(
        &row,
        json!([{"op":"replace","path":"displayName","value":"Émilie Example"}]),
    )
    .unwrap();
    assert_eq!(again, row);
}
#[test]
fn patch_primary_switches_without_two_primaries() {
    let row = person();
    let changed=patch(&row,json!([{"op":"add","path":"emails","value":[{"value":"Other@example.org","type":"home"}]},{"op":"replace","path":"emails[type eq \"home\"].primary","value":true}])).unwrap();
    assert_eq!(
        changed.data().emails.iter().filter(|e| e.primary).count(),
        1
    );
    assert!(changed.data().emails[1].primary);
}
#[test]
fn adding_existing_email_merges_and_switches_primary() {
    let row = person();
    let changed=patch(&row,json!([{"op":"add","path":"emails","value":[{"value":"Other@example.org","type":"home","primary":true}]},{"op":"add","path":"emails","value":[{"value":"Emilie@example.org","primary":true}]}])).unwrap();
    assert_eq!(changed.data().emails.len(), 2);
    assert!(changed.data().emails[0].primary);
    assert!(!changed.data().emails[1].primary);
    assert_eq!(changed.data().emails[0].kind.as_deref(), Some("work"));
}
#[test]
fn selector_handles_literal_brackets_and_escaped_quotes() {
    let row = person();
    let changed=patch(&row,json!([{"op":"replace","path":"emails","value":[{"value":"Other@example.org","type":"a]b\"c"}]},{"op":"replace","path":"emails[type eq \"a]b\\\"c\"].primary","value":true}])).unwrap();
    assert!(changed.data().emails[0].primary);
}
#[test]
fn selectors_do_not_accept_injected_trailing_expressions() {
    let row = person();
    for path in [
        "emails[type eq \"work\" or value eq \"x\"].primary",
        "emails[type eq \"work\"].primary.extra",
        "emails[type co \"work\"].primary",
        "emails[primary eq true].value",
        "emails[value eq \"bad\"]",
    ] {
        assert!(patch(&row, json!([{"op":"replace","path":path,"value":true}])).is_err());
    }
}
#[test]
fn absent_target_and_multiple_primary_targets_are_errors() {
    let row = person();
    assert_eq!(
        patch(
            &row,
            json!([{"op":"remove","path":"emails[type eq \"absent\"]"}])
        )
        .unwrap_err(),
        TARGET
    );
    assert!(patch(&row,json!([{"op":"replace","path":"emails","value":[{"value":"a@example.org","type":"work"},{"value":"b@example.org","type":"work"}]},{"op":"replace","path":"emails[type eq \"work\"].primary","value":true}])).is_err());
}
#[test]
fn removing_emails_does_not_recover_them_from_login() {
    let row = patch(&person(), json!([{"op":"remove","path":"emails"}])).unwrap();
    assert!(
        candidate(&[row]).unwrap().snapshot().people[0]
            .addresses
            .is_empty()
    );
}
#[test]
fn readonly_patch_is_refused() {
    for path in ["id", "meta", "meta.version", "schemas", "groups"] {
        assert_eq!(
            patch(&person(), json!([{"op":"replace","path":path,"value":"x"}])).unwrap_err(),
            MUTABILITY
        );
    }
}
#[test]
fn malformed_patch_does_not_succeed() {
    let row = person();
    for ops in [
        json!([]),
        json!([{"op":"replace","path":"active"}]),
        json!([{"op":"remove"}]),
        json!([{"op":"remove","path":"emails","value":[]}]),
        json!([{"op":"copy","path":"active","value":true}]),
    ] {
        assert!(patch(&row, ops).is_err());
    }
    let ops = vec![json!({"op":"replace","path":"active","value":true}); MAX_OPERATIONS + 1];
    assert_eq!(patch(&row, json!(ops)).unwrap_err(), LIMIT);
}
#[test]
fn group_add_is_idempotent_and_remove_is_explicit() {
    let p = person();
    let g = group("Team", json!([{"value":p.id()}]));
    let again = patch(
        &g,
        json!([{"op":"add","path":"members","value":[{"value":p.id()}]}]),
    )
    .unwrap();
    assert_eq!(again, g);
    let next = patch(
        &g,
        json!([{"op":"remove","path":format!("members[value eq \"{}\"]",p.id())}]),
    )
    .unwrap();
    assert!(next.data().members().is_empty());
    assert!(patch(&g,json!([{"op":"replace","path":format!("members[value eq \"{}\"]",p.id()),"value":{"value":uuid::Uuid::new_v4().to_string()}}])).is_err());
}
#[test]
fn no_network_or_group_email_inference() {
    let p = person();
    let g = group(
        "finance@example.org",
        json!([{"value":p.id(),"$ref":"https://attacker.invalid/token","display":"Manager"}]),
    );
    let c = candidate(&[p, g]).unwrap();
    assert_eq!(c.snapshot().memberships.len(), 1);
    assert!(c.snapshot().groups[0].addresses.is_empty());
    assert_eq!(c.snapshot().groups[0].activity, Activity::Unknown);
    assert!(!c.snapshot().groups[0].protected);
}
#[test]
fn candidate_rejects_missing_wrong_kind_or_cyclic_members() {
    let p = person();
    let missing = group(
        "Missing",
        json!([{"value":uuid::Uuid::new_v4().to_string()}]),
    );
    assert!(candidate(&[missing]).is_err());
    let wrong = group("Wrong kind", json!([{"value":p.id(),"type":"Group"}]));
    assert!(candidate(&[p, wrong]).is_err());
    let a = group("A", json!([]));
    let b = group("B", json!([{"value":a.id(),"type":"Group"}]));
    let a = patch(
        &a,
        json!([{"op":"add","path":"members","value":[{"value":b.id(),"type":"Group"}]}]),
    )
    .unwrap();
    assert!(candidate(&[a, b]).is_err());
}
#[test]
fn duplicate_usernames_are_source_local_case_insensitive_conflicts() {
    let a = create(ResourceType::User, user("ALICE"));
    let b = create(ResourceType::User, user("alice"));
    assert_eq!(candidate(&[a, b]).unwrap_err().status, 409);
}
#[test]
fn external_ids_remain_client_scoped_not_artificial_unique_keys() {
    let mut a = user("one");
    a["externalId"] = json!("client-id");
    let mut b = user("two");
    b["externalId"] = json!("client-id");
    assert!(candidate(&[create(ResourceType::User, a), create(ResourceType::User, b)]).is_ok());
}
#[test]
fn rows_cannot_cross_source_or_rebind_same_id_to_another_tenant() {
    let row = person();
    let bytes = row.encode(&source()).unwrap();
    let mut foreign = source();
    foreign.id = "another".into();
    assert!(Resource::decode(&bytes, &foreign).is_err());
    foreign.id = source().id;
    foreign.authority = "another-tenant".into();
    assert!(Resource::decode(&bytes, &foreign).is_err());
    let other = Resource::create(
        &foreign,
        Data::parse(
            ResourceType::User,
            &serde_json::to_vec(&user("other")).unwrap(),
        )
        .unwrap(),
        1000,
    )
    .unwrap();
    assert!(candidate(std::slice::from_ref(&other)).is_err());
    assert!(row.without_member(&other, 1001).is_err());
}
#[test]
fn deleting_a_member_invalidates_referencing_group_etags_only() {
    let p = person();
    let g = group("Team", json!([{"value":p.id()}]));
    let empty = group("Other", json!([]));
    let next = g.without_member(&p, 1001).unwrap();
    assert_ne!(next.etag(), g.etag());
    assert!(next.data().members().is_empty());
    assert_eq!(empty.without_member(&p, 1001).unwrap(), empty);
}
#[test]
fn snapshot_attestation_and_current_revision_are_bound() {
    let row = person();
    let rev = revision();
    let c = Candidate::prepare(
        source(),
        rev.clone(),
        1,
        std::slice::from_ref(&row),
        1002,
        1002,
    )
    .unwrap();
    assert!(c.verify_current(&rev).is_ok());
    assert!(c.verify_current(&rev.next().unwrap()).is_err());
    assert!(c.verify_current(&revision()).is_err());
    for time in [0, 999, 1003] {
        assert!(
            Candidate::prepare(
                source(),
                rev.clone(),
                1,
                std::slice::from_ref(&row),
                time,
                1002
            )
            .is_err()
        );
    }
    assert!(Candidate::prepare(source(), rev, 1, &[row], 1002, 1400).is_err());
}
#[test]
fn canonical_inventory_is_order_independent() {
    let a = person();
    let b = create(ResourceType::User, user("second"));
    let r = revision();
    let x =
        Candidate::prepare(source(), r.clone(), 1, &[a.clone(), b.clone()], 1002, 1002).unwrap();
    let y = Candidate::prepare(source(), r, 1, &[b, a], 1002, 1002).unwrap();
    assert_eq!(x.inventory_sha256(), y.inventory_sha256());
    assert_eq!(
        x.snapshot().digest().unwrap(),
        y.snapshot().digest().unwrap()
    );
}
#[test]
fn resources_roundtrip_and_corrupt_rows_fail_closed() {
    let row = person();
    let bytes = row.encode(&source()).unwrap();
    assert_eq!(Resource::decode(&bytes, &source()).unwrap(), row);
    for key in ["version", "created", "modified", "source_sha256", "id"] {
        let mut value: Value = serde_json::from_slice(&bytes).unwrap();
        value[key] = json!(0);
        assert!(Resource::decode(&serde_json::to_vec(&value).unwrap(), &source()).is_err());
    }
}
#[test]
fn equality_filters_are_explicit_and_no_regex_is_evaluated() {
    let row = person();
    for (filter, expected) in [
        ("userName eq \"EMILIE@example.org\"", true),
        ("active eq true", false),
        ("displayName eq \"émilie example\"", true),
        ("externalId eq \"missing\"", false),
    ] {
        assert_eq!(
            Filter::parse(ResourceType::User, filter)
                .unwrap()
                .matches(&row),
            expected
        );
    }
    for filter in [
        "userName co \"emilie\"",
        "userName eq \"x\" or active eq true",
        "password pr",
        "userName eq null",
        "active eq \"true\"",
    ] {
        assert_eq!(
            Filter::parse(ResourceType::User, filter)
                .unwrap_err()
                .scim_type,
            "invalidFilter"
        );
    }
    assert!(Filter::parse(ResourceType::Group, "userName eq \"x\"").is_err());
}
#[test]
fn external_id_filter_is_case_exact() {
    let mut u = user("employee");
    u["externalId"] = json!("ClientA");
    let row = create(ResourceType::User, u);
    assert!(
        Filter::parse(ResourceType::User, "externalId eq \"ClientA\"")
            .unwrap()
            .matches(&row)
    );
    assert!(
        !Filter::parse(ResourceType::User, "externalId eq \"clienta\"")
            .unwrap()
            .matches(&row)
    );
}
#[test]
fn bounded_pagination_and_count_zero() {
    let q = ListQuery::parse(
        ResourceType::User,
        &[
            ("count".into(), "0".into()),
            ("startIndex".into(), "0".into()),
        ],
    )
    .unwrap();
    assert_eq!(q.response(999, &[]).unwrap()["totalResults"], 999);
    assert!(q.response(999, &[person()]).is_err());
    let q = ListQuery::parse(
        ResourceType::User,
        &[
            ("count".into(), "-1".into()),
            ("startIndex".into(), "-2".into()),
        ],
    )
    .unwrap();
    assert_eq!(q.count, 0);
    assert_eq!(q.start_index, 1);
    assert_eq!(
        ListQuery::parse(ResourceType::Group, &[("count".into(), "999999".into())])
            .unwrap()
            .count,
        100
    );
    for args in [
        vec![
            ("filter".into(), "id eq \"x\"".into()),
            ("filter".into(), "id eq \"y\"".into()),
        ],
        vec![("sortBy".into(), "displayName".into())],
        vec![("attributes".into(), "password".into())],
    ] {
        assert!(ListQuery::parse(ResourceType::User, &args).is_err());
    }
}
#[test]
fn caps_apply_before_accepting_provider_data() {
    assert_eq!(
        Data::parse(ResourceType::User, &vec![b' '; MAX_BODY_BYTES + 1]).unwrap_err(),
        LIMIT
    );
    let mut u = user("employee");
    u["emails"] = json!(
        (0..33)
            .map(|i| json!({"value":format!("a{i}@example.org")}))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        Data::parse(ResourceType::User, &serde_json::to_vec(&u).unwrap()).unwrap_err(),
        LIMIT
    );
    let g = json!({"schemas":[GROUP_SCHEMA],"displayName":"Large","members":vec![json!({"value":uuid::Uuid::new_v4().to_string()});MAX_MEMBERS+1]});
    assert_eq!(
        Data::parse(ResourceType::Group, &serde_json::to_vec(&g).unwrap()).unwrap_err(),
        LIMIT
    );
}
#[test]
fn diagnostics_do_not_echo_untrusted_content() {
    let secret = "private-provider-value";
    let err = Data::parse(
        ResourceType::User,
        format!("{{\"userName\":\"{secret}\"}}").as_bytes(),
    )
    .unwrap_err();
    assert!(!err.to_string().contains(secret));
    assert!(!err.body().to_string().contains(secret));
    assert_eq!(err.body()["status"], "400");
}

#[test]
fn duplicate_member_add_at_capacity_is_a_no_op() {
    let members: Vec<_> = (0..MAX_MEMBERS)
        .map(|_| json!({"value":uuid::Uuid::new_v4().to_string()}))
        .collect();
    let g = group("Large", json!(members));
    assert_eq!(
        patch(
            &g,
            json!([{"op":"add","path":"members","value":[members[0].clone()]}])
        )
        .unwrap(),
        g
    );
    assert_eq!(patch(&g,json!([{"op":"add","path":"members","value":[{"value":uuid::Uuid::new_v4().to_string()}]}])).unwrap_err(),LIMIT);
}
#[test]
fn stale_no_op_patch_never_overrides_the_precondition() {
    let row = person();
    let bytes=serde_json::to_vec(&json!({"schemas":[PATCH_SCHEMA],"Operations":[{"op":"replace","path":"displayName","value":"Émilie Example"}]})).unwrap();
    assert_eq!(
        row.patch(&bytes, Some("W/\"obsolete\""), 1001).unwrap_err(),
        STALE
    );
}
#[test]
fn conflicting_primaries_and_duplicate_aliases_fail() {
    for emails in [
        json!([{"value":"a@example.org","primary":true},{"value":"b@example.org","primary":true}]),
        json!([{"value":"a@EXAMPLE.ORG"},{"value":"a@example.org"}]),
    ] {
        let mut u = user("employee");
        u["emails"] = emails;
        assert!(Data::parse(ResourceType::User, &serde_json::to_vec(&u).unwrap()).is_err());
    }
}
#[test]
fn a_resource_id_can_occur_only_once_in_an_inventory() {
    let row = person();
    assert!(candidate(&[row.clone(), row]).is_err());
}
#[test]
fn exhausted_sequences_refuse_to_wrap() {
    let mut rev = revision();
    rev.sequence = i64::MAX as u64;
    assert!(rev.next().is_err());
    let row = person();
    let mut saved: Value = serde_json::from_slice(&row.encode(&source()).unwrap()).unwrap();
    saved["version"] = json!(i64::MAX);
    let row = Resource::decode(&serde_json::to_vec(&saved).unwrap(), &source()).unwrap();
    assert_eq!(
        patch(&row, json!([{"op":"replace","path":"active","value":true}])).unwrap_err(),
        LIMIT
    );
}
#[test]
fn deep_readonly_values_do_not_evade_request_bounds() {
    let mut value = json!("end");
    for _ in 0..14 {
        value = json!([value]);
    }
    let mut u = user("employee");
    u["meta"] = value;
    assert_eq!(
        Data::parse(ResourceType::User, &serde_json::to_vec(&u).unwrap()).unwrap_err(),
        LIMIT
    );
}

#[test]
fn member_value_selectors_are_case_exact_even_for_noncanonical_literals() {
    let id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    let g = group("Team", json!([{"value":id}]));
    assert_eq!(
        patch(
            &g,
            json!([{"op":"remove","path":format!("members[value eq \"{}\"]",id.to_uppercase())}])
        )
        .unwrap_err(),
        TARGET
    );
}
