use proxsep_core::profile::Profile;

const PROFILE: &str = r#"<ProxifierProfile version="102" platform="Windows" product_id="7" product_minver="414" vendor="keep"><Options><Encryption mode="none"/><VendorOption enabled="true"/></Options><ProxyList><Proxy id="100" type="SOCKS5"><Address>localhost</Address><Port>1080</Port><Authentication enabled="true"><Username>user</Username><Password>pass</Password></Authentication><Future>keep</Future></Proxy></ProxyList><ChainList><Chain id="101" type="redundancy"><Name>Fallback</Name><Proxy enabled="true">100</Proxy><RedundancyTryDirect>true</RedundancyTryDirect></Chain></ChainList><RuleList><Rule enabled="true"><Name>Default</Name><Action type="Chain">101</Action></Rule></RuleList></ProxifierProfile>"#;

#[test]
fn nested_authentication_is_not_silently_discarded() {
    let p = Profile::from_xml(PROFILE).unwrap();
    assert_eq!(p.proxies[0].username.as_deref(), Some("user"));
    assert_eq!(p.proxies[0].password.as_deref(), Some("pass"));
    assert_eq!(p.chains[0].proxy_ids, vec![100]);
}

#[test]
fn unknown_fields_and_product_metadata_survive_save() {
    let p = Profile::from_xml(PROFILE).unwrap();
    let out = p.to_xml().unwrap();
    assert!(out.contains("product_id=\"7\""));
    assert!(out.contains("VendorOption"));
    assert!(out.contains("<Future>keep</Future>"));
    assert!(out.contains("type=\"Chain\""));
}

#[test]
fn malformed_boolean_and_unknown_action_are_errors() {
    assert!(Profile::from_xml(&PROFILE.replace("enabled=\"true\"", "enabled=\"banana\"")).is_err());
    assert!(Profile::from_xml(&PROFILE.replace("type=\"Chain\"", "type=\"Unknown\"")).is_err());
    assert!(Profile::from_xml("<NotAProfile/>").is_err());
}

#[test]
fn plaintext_mode_uses_original_disabled_enum_and_protected_edits_fail_safe() {
    assert_eq!(Profile::default().options.encryption_mode, "disabled");
    let mut p = Profile::from_xml(&PROFILE.replace("mode=\"none\"", "mode=\"basic\"")).unwrap();
    assert!(p.to_xml().is_ok());
    p.proxies[0].password = Some("changed plaintext".into());
    assert!(p.to_xml().is_err());
}

#[test]
fn protected_password_preservation_does_not_forbid_username_edits() {
    let mut p = Profile::from_xml(&PROFILE.replace("mode=\"none\"", "mode=\"basic\"")).unwrap();
    p.proxies[0].username = Some("changed-plain-username".into());
    let out = p.to_xml().unwrap();
    let restored = Profile::from_xml(&out).unwrap();
    assert_eq!(
        restored.proxies[0].username.as_deref(),
        Some("changed-plain-username")
    );
    assert_eq!(restored.proxies[0].password.as_deref(), Some("pass"));
}

#[test]
fn new_account_and_master_modes_require_the_unimplemented_hash_backend() {
    for mode in ["account", "master"] {
        let p = Profile {
            options: proxsep_core::profile::Options {
                encryption_mode: mode.into(),
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(
            p.to_xml().is_err(),
            "must not invent a protected Hash for {mode}"
        );
    }
}

#[test]
fn switching_to_plaintext_requires_replacing_opaque_passwords() {
    let mut p = Profile::from_xml(&PROFILE.replace("mode=\"none\"", "mode=\"basic\"")).unwrap();
    p.options.encryption_mode = "disabled".into();
    let copied = proxsep_core::profile::Proxy {
        id: 999,
        ..p.proxies[0].clone()
    };
    assert!(
        p.password_is_protected(&copied).unwrap(),
        "copying/reassigning an ID does not decrypt a carrier"
    );
    assert!(
        p.to_xml().is_err(),
        "an opaque carrier must not be relabeled as plaintext"
    );
    p.proxies[0].password = Some("new-explicit-plain-password".into());
    assert!(p.to_xml().is_ok());
}
