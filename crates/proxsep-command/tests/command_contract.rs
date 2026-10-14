use std::collections::HashSet;

use proxsep_command::{CommandContext, CommandRequest, CommandSurface};
use proxsep_core::profile::Profile;
use serde_json::json;

#[test]
fn standard_catalog_is_unique_schema_backed_and_shared_by_every_surface() {
    let registry = proxsep_command::CommandRegistry::standard();
    assert!(
        registry.len() >= 12,
        "the first catalog slice must be useful"
    );
    let descriptors = registry.descriptors();
    let ids = descriptors
        .iter()
        .map(|descriptor| descriptor.id.as_str())
        .collect::<HashSet<_>>();
    assert_eq!(ids.len(), descriptors.len());
    for descriptor in descriptors {
        assert!(
            descriptor
                .id
                .chars()
                .all(|character| character.is_ascii_lowercase()
                    || character == '.'
                    || character == '_')
        );
        assert_eq!(
            descriptor.surfaces,
            vec![
                CommandSurface::Ui,
                CommandSurface::Cli,
                CommandSurface::Json,
                CommandSurface::Mcp,
            ]
        );
        assert!(descriptor.input_schema.is_object());
        assert!(descriptor.output_schema.is_object());
    }
}

#[test]
fn profile_and_route_commands_execute_through_the_same_json_contract() {
    let registry = proxsep_command::CommandRegistry::standard();
    let xml = include_str!("../../proxsep-core/tests/fixtures/default.ppx");
    let summary = registry
        .execute(
            &CommandContext::default(),
            "profile.summary",
            json!({ "xml": xml }),
        )
        .unwrap();
    assert_eq!(summary["version"], 102);
    assert_eq!(summary["rules"], 2);

    let route = registry
        .execute(
            &CommandContext::default(),
            "route.decide",
            json!({
                "xml": xml,
                "application": "browser.exe",
                "target": "example.com",
                "port": 443
            }),
        )
        .unwrap();
    assert!(route["rule"].is_string());
    assert!(route["action"].is_string());
}

#[test]
fn request_envelope_preserves_identity_and_stable_errors() {
    let registry = proxsep_command::CommandRegistry::standard();
    let response = registry.execute_request(
        &CommandContext::default(),
        CommandRequest {
            request_id: Some("automation-42".into()),
            command: "missing.command".into(),
            arguments: json!({}),
        },
    );
    assert_eq!(response.request_id.as_deref(), Some("automation-42"));
    assert_eq!(response.command, "missing.command");
    assert!(!response.ok);
    assert_eq!(response.error.unwrap().code, "unknown_command");

    let malformed = registry.execute_json(&CommandContext::default(), "not json");
    assert!(!malformed.ok);
    assert_eq!(malformed.error.unwrap().code, "invalid_request");

    let unknown_envelope_field = registry.execute_json(
        &CommandContext::default(),
        r#"{"command":"system.command.count","unexpected":true}"#,
    );
    assert!(!unknown_envelope_field.ok);
    assert_eq!(
        unknown_envelope_field.error.unwrap().code,
        "invalid_request"
    );

    let extra = registry.execute_request(
        &CommandContext::default(),
        CommandRequest {
            request_id: None,
            command: "system.command.count".into(),
            arguments: json!({ "ignored": true }),
        },
    );
    assert!(!extra.ok);
    assert_eq!(extra.error.unwrap().code, "invalid_arguments");
}

#[test]
fn catalog_can_describe_itself_through_a_normal_command() {
    let registry = proxsep_command::CommandRegistry::standard();
    let listed = registry
        .execute(&CommandContext::default(), "system.command.list", json!({}))
        .unwrap();
    assert_eq!(listed.as_array().unwrap().len(), registry.len());
    let described = registry
        .execute(
            &CommandContext::default(),
            "system.command.describe",
            json!({ "id": "route.trace" }),
        )
        .unwrap();
    assert_eq!(described["id"], "route.trace");
    let describe_command = registry.descriptor("system.command.describe").unwrap();
    assert!(describe_command.input_schema["properties"]["id"].is_object());
    assert!(describe_command.input_schema["properties"]["field"].is_null());
    let counts = registry
        .execute(
            &CommandContext::default(),
            "system.command.count",
            json!({}),
        )
        .unwrap();
    assert_eq!(counts["total"], registry.len());
    assert!(counts["risks"]["read_only"].as_u64().unwrap() > 0);
    assert!(counts["risks"]["mutating"].as_u64().unwrap() > 0);
}

#[test]
fn runtime_commands_share_one_explicit_context() {
    let registry = proxsep_command::CommandRegistry::standard();
    let missing = registry.execute_request(
        &CommandContext::default(),
        CommandRequest {
            request_id: None,
            command: "runtime.connection.list".into(),
            arguments: json!({}),
        },
    );
    assert_eq!(missing.error.unwrap().code, "runtime_required");

    let xml = include_str!("../../proxsep-core/tests/fixtures/default.ppx");
    let profile = Profile::from_xml_for_current_user(xml).unwrap();
    let context = CommandContext {
        runtime: Some(proxsep_runtime::Runtime::new(profile)),
    };
    let applied = registry
        .execute(&context, "runtime.profile.replace", json!({ "xml": xml }))
        .unwrap();
    assert_eq!(applied["applied"], true);

    let connections = registry
        .execute(&context, "runtime.connection.list", json!({}))
        .unwrap();
    assert_eq!(connections, json!([]));
}

#[test]
fn every_profile_option_has_real_get_and_set_commands() {
    let registry = proxsep_command::CommandRegistry::standard();
    assert!(registry.len() >= 49);
    let xml = include_str!("../../proxsep-core/tests/fixtures/default.ppx");
    let cases = [
        ("resolve.auto_mode_detection", json!(false)),
        ("resolve.via_proxy", json!(true)),
        ("resolve.block_non_a_types", json!(true)),
        ("resolve.exclusion_list", json!("localhost; *.internal")),
        ("resolve.exclusion_only_from_list", json!(true)),
        ("resolve.dns_udp_mode", json!(2)),
        ("encryption_mode", json!("disabled")),
        ("connection_loop_detection", json!(false)),
        ("connection_loop_resolve", json!(false)),
        ("udp_mode", json!("mode_block_all")),
        ("leak_prevention", json!(true)),
        ("process_other_users", json!(true)),
        ("process_services", json!(true)),
        ("handle_direct_connections", json!(true)),
        ("http_proxies_support", json!(true)),
    ];

    for (field, replacement) in cases {
        let get_id = format!("options.{field}.get");
        let set_id = format!("options.{field}.set");
        assert!(registry.descriptor(&get_id).is_some(), "missing {get_id}");
        assert!(registry.descriptor(&set_id).is_some(), "missing {set_id}");

        let original = registry
            .execute(&CommandContext::default(), &get_id, json!({ "xml": xml }))
            .unwrap();
        assert!(original.get("value").is_some(), "{get_id} has no value");

        let changed = registry
            .execute(
                &CommandContext::default(),
                &set_id,
                json!({ "xml": xml, "value": replacement }),
            )
            .unwrap();
        let changed_xml = changed["xml"].as_str().unwrap();
        let round_trip = registry
            .execute(
                &CommandContext::default(),
                &get_id,
                json!({ "xml": changed_xml }),
            )
            .unwrap();
        assert_eq!(round_trip["value"], replacement, "{set_id} did not persist");
    }
}

#[test]
fn aggregate_options_command_is_credential_safe_and_setters_are_strict() {
    let registry = proxsep_command::CommandRegistry::standard();
    let xml = include_str!("../../proxsep-core/tests/fixtures/default.ppx");
    let options = registry
        .execute(
            &CommandContext::default(),
            "options.get",
            json!({ "xml": xml }),
        )
        .unwrap();
    assert_eq!(options["resolve"]["auto_mode_detection"], true);
    assert_eq!(options["encryption_mode"], "basic");
    assert!(options.get("password").is_none());

    let invalid = registry.execute_request(
        &CommandContext::default(),
        CommandRequest {
            request_id: None,
            command: "options.resolve.dns_udp_mode.set".into(),
            arguments: json!({ "xml": xml, "value": 256 }),
        },
    );
    assert!(!invalid.ok);
    assert_eq!(invalid.error.unwrap().code, "invalid_arguments");

    let extra = registry.execute_request(
        &CommandContext::default(),
        CommandRequest {
            request_id: None,
            command: "options.process_services.set".into(),
            arguments: json!({ "xml": xml, "value": true, "unexpected": 1 }),
        },
    );
    assert!(!extra.ok);
    assert_eq!(extra.error.unwrap().code, "invalid_arguments");

    let plaintext = Profile::default().to_xml().unwrap();
    let unsupported = registry.execute_request(
        &CommandContext::default(),
        CommandRequest {
            request_id: None,
            command: "options.encryption_mode.set".into(),
            arguments: json!({ "xml": plaintext, "value": "master" }),
        },
    );
    assert!(!unsupported.ok);
    assert_eq!(unsupported.error.unwrap().code, "command_failed");
}

fn profile_with_proxy() -> String {
    include_str!("../../proxsep-core/tests/fixtures/default.ppx").replace(
        "<ProxyList />",
        r#"<ProxyList>
    <Proxy id="1" type="SOCKS5">
      <Address>127.0.0.1</Address><Port>1080</Port><Label>Local</Label>
      <UserAgent>ProxSep Test</UserAgent><Options>0</Options>
      <Authentication enabled="true"><Username>alice</Username><Password>secret</Password></Authentication>
    </Proxy>
  </ProxyList>"#,
    )
}

#[test]
fn proxy_inventory_and_reference_commands_are_credential_safe() {
    let registry = proxsep_command::CommandRegistry::standard();
    assert!(registry.len() >= 66);
    let xml = profile_with_proxy();

    let listed = registry
        .execute(
            &CommandContext::default(),
            "proxy.list",
            json!({ "xml": xml }),
        )
        .unwrap();
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert_eq!(listed[0]["id"], 1);
    assert_eq!(listed[0]["has_username"], true);
    assert_eq!(listed[0]["has_password"], true);
    assert!(listed[0].get("username").is_none());
    assert!(listed[0].get("password").is_none());

    let count = registry
        .execute(
            &CommandContext::default(),
            "proxy.count",
            json!({ "xml": xml }),
        )
        .unwrap();
    assert_eq!(count["count"], 1);
    let next = registry
        .execute(
            &CommandContext::default(),
            "proxy.id.next",
            json!({ "xml": xml }),
        )
        .unwrap();
    assert_eq!(next["id"], 2);
    let references = registry
        .execute(
            &CommandContext::default(),
            "proxy.references",
            json!({ "xml": xml, "id": 1 }),
        )
        .unwrap();
    assert_eq!(references["chains"], json!([]));
    assert_eq!(references["rules"], json!([]));
}

#[test]
fn proxy_field_commands_round_trip_validated_profile_xml() {
    let registry = proxsep_command::CommandRegistry::standard();
    let xml = profile_with_proxy();
    let cases = [
        ("protocol", json!("HTTPS")),
        ("address", json!("proxy.internal")),
        ("port", json!(8443)),
        ("label", json!("Corporate")),
        ("user_agent", json!("ProxSep/1")),
        ("options", json!(7)),
    ];
    for (field, replacement) in cases {
        let get_id = format!("proxy.{field}.get");
        let set_id = format!("proxy.{field}.set");
        assert!(registry.descriptor(&get_id).is_some(), "missing {get_id}");
        assert!(registry.descriptor(&set_id).is_some(), "missing {set_id}");
        let changed = registry
            .execute(
                &CommandContext::default(),
                &set_id,
                json!({ "xml": xml, "id": 1, "value": replacement }),
            )
            .unwrap();
        let read = registry
            .execute(
                &CommandContext::default(),
                &get_id,
                json!({ "xml": changed["xml"], "id": 1 }),
            )
            .unwrap();
        assert_eq!(read["value"], replacement, "{set_id} did not persist");
    }

    let missing = registry.execute_request(
        &CommandContext::default(),
        CommandRequest {
            request_id: None,
            command: "proxy.get".into(),
            arguments: json!({ "xml": xml, "id": 99 }),
        },
    );
    assert_eq!(missing.error.unwrap().code, "not_found");
}
