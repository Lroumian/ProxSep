use proxsep_core::profile::Profile;

const DEFAULT_PROFILE: &str = include_str!("fixtures/default.ppx");

#[test]
fn parses_observed_proxifier_4_profile() {
    let profile = Profile::from_xml(DEFAULT_PROFILE).expect("profile parses");

    assert_eq!(profile.version, 102);
    assert_eq!(profile.platform, "Windows");
    assert!(profile.options.resolve.auto_mode_detection);
    assert!(!profile.options.resolve.via_proxy);
    assert_eq!(profile.rules.len(), 2);
    assert_eq!(profile.rules[0].name, "Localhost");
}

#[test]
fn round_trip_preserves_routing_semantics() {
    let profile = Profile::from_xml(DEFAULT_PROFILE).expect("profile parses");
    let xml = profile.to_xml().expect("profile serializes");
    let reparsed = Profile::from_xml(&xml).expect("serialized profile parses");

    assert_eq!(reparsed.rules, profile.rules);
    assert_eq!(reparsed.proxies, profile.proxies);
    assert_eq!(reparsed.options, profile.options);
}
