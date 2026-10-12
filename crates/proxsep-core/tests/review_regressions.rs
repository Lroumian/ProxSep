use proxsep_core::{
    profile::{Action, Chain, Profile, Rule},
    rules::{Connection, RuleEngine},
};
use xmltree::{Element, XMLNode};

#[test]
fn wildcard_port_matches_when_mixed_with_other_patterns() {
    for ports in ["*;443", "443,*", "80-81; * ;443"] {
        let profile = Profile {
            rules: vec![Rule {
                name: "Block".into(),
                ports: ports.into(),
                action: Action::Block,
                ..Default::default()
            }],
            ..Default::default()
        };
        profile.validate().unwrap();
        for port in [1, 80, 443, 65535] {
            assert_eq!(
                RuleEngine::new(&profile.rules)
                    .decide(&Connection::new("app", "127.0.0.1", port))
                    .action,
                &Action::Block,
                "{ports} at {port}"
            );
        }
    }
}

fn extension_profile() -> Profile {
    Profile::from_xml(r#"<ProxifierProfile version="102"><RuleList>
      <Rule enabled="true" vendor="first"><Name>Duplicate</Name><Action type="Direct" custom="first"/><Future>first</Future></Rule>
      <Rule enabled="true" vendor="second"><Name>Duplicate</Name><Action type="Block" custom="second"/><Future>second</Future></Rule>
      <Rule enabled="true"><Name>Default</Name><Action type="Direct"/></Rule>
    </RuleList></ProxifierProfile>"#).unwrap()
}

fn saved_rules(profile: &Profile) -> Vec<Element> {
    let xml = profile.to_xml().unwrap();
    let root = Element::parse(xml.as_bytes()).unwrap();
    root.get_child("RuleList")
        .unwrap()
        .children
        .iter()
        .filter_map(XMLNode::as_element)
        .filter(|element| element.name == "Rule")
        .cloned()
        .collect()
}

fn assert_extensions(rule: &Element, marker: &str) {
    assert_eq!(
        rule.attributes.get("vendor").map(String::as_str),
        Some(marker)
    );
    assert_eq!(
        rule.get_child("Future").unwrap().get_text().as_deref(),
        Some(marker)
    );
    assert_eq!(
        rule.get_child("Action")
            .unwrap()
            .attributes
            .get("custom")
            .map(String::as_str),
        Some(marker)
    );
}

#[test]
fn renaming_and_reordering_rules_preserves_owned_extensions() {
    let mut profile = extension_profile();
    profile.rules[0].name = "Renamed".into();
    profile.rules.swap(0, 1);
    let rules = saved_rules(&profile);
    assert_extensions(&rules[0], "second");
    assert_extensions(&rules[1], "first");
    assert_eq!(
        rules[1].get_child("Name").unwrap().get_text().as_deref(),
        Some("Renamed")
    );
    // Reopening and editing another field must keep the same opaque metadata.
    let mut reopened = Profile::from_xml(&profile.to_xml().unwrap()).unwrap();
    reopened.rules[1].ports = "443".into();
    assert_extensions(&saved_rules(&reopened)[1], "first");
}

#[test]
fn duplicate_rule_names_do_not_alias_extension_nodes() {
    let profile = extension_profile();
    let rules = saved_rules(&profile);
    assert_extensions(&rules[0], "first");
    assert_extensions(&rules[1], "second");
}

#[test]
fn native_profile_version_range_is_enforced_on_load_and_save() {
    for version in [100, 101, 102] {
        let xml = format!("<ProxifierProfile version=\"{version}\"/>");
        assert!(Profile::from_xml(&xml).is_ok());
    }
    for version in [0, 99, 103, u32::MAX] {
        let xml = format!("<ProxifierProfile version=\"{version}\"/>");
        assert!(Profile::from_xml(&xml).is_err(), "version {version}");
        let profile = Profile {
            version,
            ..Default::default()
        };
        assert!(profile.to_xml().is_err(), "export version {version}");
    }
}

#[test]
fn imported_profiles_require_the_native_version_attribute() {
    assert!(Profile::from_xml("<ProxifierProfile/>").is_err());
    assert!(Profile::from_xml("<ProxifierProfile version=\"\"/>").is_err());
    assert_eq!(Profile::default().version, 102);
    assert!(Profile::from_xml(&Profile::default().to_xml().unwrap()).is_ok());
}

#[test]
fn redundancy_timeout_obeys_the_observed_native_range() {
    for timeout in [1, 9999] {
        let profile = Profile {
            chains: vec![Chain {
                kind: "redundancy".into(),
                redundancy_timeout: timeout,
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(profile.validate().is_ok());
        assert!(Profile::from_xml(&profile.to_xml().unwrap()).is_ok());
    }
    for timeout in [0, 10000, u32::MAX] {
        let profile = Profile {
            chains: vec![Chain {
                kind: "redundancy".into(),
                redundancy_timeout: timeout,
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(profile.validate().is_err(), "timeout {timeout}");
    }
}

#[test]
fn dns_free_decision_preserves_possible_earlier_ip_rule_priority() {
    for targets in [
        "192.0.2.10",
        "192.0.2.0/24",
        "192.0.2.1-192.0.2.20",
        "2001:db8::1",
    ] {
        let rules = [
            Rule {
                name: "IP proxy".into(),
                targets: targets.into(),
                action: Action::Proxy("1".into()),
                ..Default::default()
            },
            Rule {
                name: "Default".into(),
                action: Action::Block,
                ..Default::default()
            },
        ];
        assert!(
            RuleEngine::new(&rules)
                .decide_without_dns(&Connection::new("app", "example.com", 443))
                .is_none(),
            "{targets}"
        );
    }
}

#[test]
fn dns_free_decision_can_confirm_hostname_block_before_ip_rules() {
    let rules = [
        Rule {
            name: "Hostname block".into(),
            targets: "*.example.com".into(),
            action: Action::Block,
            ..Default::default()
        },
        Rule {
            name: "IP proxy".into(),
            targets: "192.0.2.0/24".into(),
            action: Action::Proxy("1".into()),
            ..Default::default()
        },
    ];
    assert_eq!(
        RuleEngine::new(&rules)
            .decide_without_dns(&Connection::new("app", "www.example.com", 443))
            .unwrap()
            .action,
        &Action::Block
    );
}

#[test]
fn irrelevant_ip_rules_do_not_require_dns_before_blocking() {
    for rule in [
        Rule {
            applications: "other.exe".into(),
            ..Default::default()
        },
        Rule {
            ports: "22".into(),
            ..Default::default()
        },
        Rule {
            interface_id: "down".into(),
            skip_if_interface_down: true,
            ..Default::default()
        },
        Rule {
            enabled: false,
            ..Default::default()
        },
    ] {
        let rules = [
            Rule {
                name: "IP proxy".into(),
                targets: "192.0.2.0/24".into(),
                action: Action::Proxy("1".into()),
                ..rule
            },
            Rule {
                name: "Default".into(),
                action: Action::Block,
                ..Default::default()
            },
        ];
        assert_eq!(
            RuleEngine::new(&rules)
                .decide_without_dns(&Connection::new("app", "example.com", 443))
                .unwrap()
                .action,
            &Action::Block
        );
    }
}

#[test]
fn dns_free_decision_uses_existing_addresses_and_certain_mixed_target_matches() {
    let rules = [Rule {
        targets: "192.0.2.0/24;*.example.com".into(),
        action: Action::Block,
        ..Default::default()
    }];
    assert_eq!(
        RuleEngine::new(&rules)
            .decide_without_dns(&Connection::new("app", "www.example.com", 443))
            .unwrap()
            .action,
        &Action::Block
    );
    assert_eq!(
        RuleEngine::new(&rules)
            .decide_without_dns(&Connection::new("app", "192.0.2.10", 443))
            .unwrap()
            .action,
        &Action::Block
    );
    let mut connection = Connection::new("app", "unlisted.example", 443);
    connection.resolved_ips.push("192.0.2.10".parse().unwrap());
    assert_eq!(
        RuleEngine::new(&rules)
            .decide_without_dns(&connection)
            .unwrap()
            .action,
        &Action::Block
    );
}
