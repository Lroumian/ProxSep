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

fn profile_with_chain() -> String {
    profile_with_proxy()
        .replace(
            "</ProxyList>",
            r#"    <Proxy id="2" type="SOCKS5">
      <Address>192.0.2.2</Address><Port>1081</Port><Label>Backup</Label>
      <UserAgent></UserAgent><Options>0</Options>
    </Proxy>
  </ProxyList>"#,
        )
        .replace(
            "<ChainList />",
            r#"<ChainList>
    <Chain id="10" type="simple">
      <Name>Main Chain</Name><Proxy enabled="true">1</Proxy><Proxy enabled="true">2</Proxy>
      <RedundancyTimeout>10</RedundancyTimeout><RedundancyTryDirect>false</RedundancyTryDirect>
      <RedundancyRecheck>true</RedundancyRecheck><RedundancyRecheckTime>60</RedundancyRecheckTime>
      <LoadBalancingSameProxyForPid>false</LoadBalancingSameProxyForPid>
    </Chain>
  </ChainList>"#,
        )
}

#[test]
fn chain_inventory_ids_and_references_use_the_validated_profile_model() {
    let registry = proxsep_command::CommandRegistry::standard();
    assert!(registry.len() >= 89);
    let xml = profile_with_chain();

    let listed = registry
        .execute(
            &CommandContext::default(),
            "chain.list",
            json!({ "xml": xml }),
        )
        .unwrap();
    assert_eq!(listed.as_array().unwrap().len(), 1);
    assert_eq!(listed[0]["id"], 10);
    assert_eq!(listed[0]["proxy_ids"], json!([1, 2]));
    let fetched = registry
        .execute(
            &CommandContext::default(),
            "chain.get",
            json!({ "xml": xml, "id": 10 }),
        )
        .unwrap();
    assert_eq!(fetched["name"], "Main Chain");
    let count = registry
        .execute(
            &CommandContext::default(),
            "chain.count",
            json!({ "xml": xml }),
        )
        .unwrap();
    assert_eq!(count["count"], 1);
    let next = registry
        .execute(
            &CommandContext::default(),
            "chain.id.next",
            json!({ "xml": xml }),
        )
        .unwrap();
    assert_eq!(next["id"], 3);
    let proxy_next = registry
        .execute(
            &CommandContext::default(),
            "proxy.id.next",
            json!({ "xml": xml }),
        )
        .unwrap();
    assert_eq!(proxy_next["id"], 3);
    let references = registry
        .execute(
            &CommandContext::default(),
            "chain.references",
            json!({ "xml": xml, "id": 10 }),
        )
        .unwrap();
    assert_eq!(references["rules"], json!([]));
}

#[test]
fn every_chain_field_has_real_get_and_set_commands() {
    let registry = proxsep_command::CommandRegistry::standard();
    let xml = profile_with_chain();
    let cases = [
        ("name", json!("Failover")),
        ("kind", json!("redundancy")),
        ("proxy_ids", json!([2, 1])),
        ("disabled_proxy_ids", json!([2])),
        ("redundancy_timeout", json!(25)),
        ("redundancy_try_direct", json!(true)),
        ("redundancy_recheck", json!(false)),
        ("redundancy_recheck_time", json!(120)),
        ("load_balancing_same_proxy_for_pid", json!(true)),
    ];
    for (field, replacement) in cases {
        let get_id = format!("chain.{field}.get");
        let set_id = format!("chain.{field}.set");
        assert!(registry.descriptor(&get_id).is_some(), "missing {get_id}");
        assert!(registry.descriptor(&set_id).is_some(), "missing {set_id}");
        let changed = registry
            .execute(
                &CommandContext::default(),
                &set_id,
                json!({ "xml": xml, "id": 10, "value": replacement }),
            )
            .unwrap();
        let read = registry
            .execute(
                &CommandContext::default(),
                &get_id,
                json!({ "xml": changed["xml"], "id": 10 }),
            )
            .unwrap();
        assert_eq!(read["value"], replacement, "{set_id} did not persist");
    }

    let invalid = registry.execute_request(
        &CommandContext::default(),
        CommandRequest {
            request_id: None,
            command: "chain.disabled_proxy_ids.set".into(),
            arguments: json!({ "xml": xml, "id": 10, "value": [99] }),
        },
    );
    assert!(!invalid.ok);
    assert_eq!(invalid.error.unwrap().code, "invalid_arguments");
}

#[test]
fn proxy_lifecycle_endpoint_and_credential_commands_are_safe() {
    let registry = proxsep_command::CommandRegistry::standard();
    assert!(registry.len() >= 98);
    let base = include_str!("../../proxsep-core/tests/fixtures/default.ppx");

    let protocols = registry
        .execute(&CommandContext::default(), "proxy.protocol.list", json!({}))
        .unwrap();
    assert_eq!(protocols.as_array().unwrap().len(), 5);

    let created = registry
        .execute(
            &CommandContext::default(),
            "proxy.create",
            json!({
                "xml": base,
                "protocol": "SOCKS5",
                "address": "proxy.example",
                "port": 1080,
                "label": "Primary"
            }),
        )
        .unwrap();
    assert_eq!(created["proxy"]["id"], 1);
    let created_xml = created["xml"].as_str().unwrap();

    let endpoint = registry
        .execute(
            &CommandContext::default(),
            "proxy.endpoint.get",
            json!({ "xml": created_xml, "id": 1 }),
        )
        .unwrap();
    assert_eq!(endpoint["address"], "proxy.example");
    assert_eq!(endpoint["port"], 1080);
    let changed = registry
        .execute(
            &CommandContext::default(),
            "proxy.endpoint.set",
            json!({ "xml": created_xml, "id": 1, "address": "proxy.internal", "port": 8443 }),
        )
        .unwrap();
    assert_eq!(changed["address"], "proxy.internal");
    assert_eq!(changed["port"], 8443);

    let duplicated = registry
        .execute(
            &CommandContext::default(),
            "proxy.duplicate",
            json!({ "xml": changed["xml"], "id": 1 }),
        )
        .unwrap();
    assert_eq!(duplicated["proxy"]["id"], 2);
    assert_eq!(duplicated["credentials_copied"], false);
    let deleted = registry
        .execute(
            &CommandContext::default(),
            "proxy.delete",
            json!({ "xml": duplicated["xml"], "id": 2 }),
        )
        .unwrap();
    assert_eq!(deleted["deleted"]["id"], 2);

    let referenced = registry.execute_request(
        &CommandContext::default(),
        CommandRequest {
            request_id: None,
            command: "proxy.delete".into(),
            arguments: json!({ "xml": profile_with_chain(), "id": 1 }),
        },
    );
    assert_eq!(referenced.error.unwrap().code, "conflict");

    let protected = profile_with_proxy();
    let status = registry
        .execute(
            &CommandContext::default(),
            "proxy.credentials.status",
            json!({ "xml": protected, "id": 1 }),
        )
        .unwrap();
    assert_eq!(status["has_username"], true);
    assert_eq!(status["has_password"], true);
    assert_eq!(status["password_protected"], true);
    assert!(status.get("username").is_none());
    assert!(status.get("password").is_none());

    let cleared = registry
        .execute(
            &CommandContext::default(),
            "proxy.credentials.clear",
            json!({ "xml": protected, "id": 1 }),
        )
        .unwrap();
    assert_eq!(cleared["has_username"], false);
    assert_eq!(cleared["has_password"], false);

    let plaintext = protected.replace("mode=\"basic\"", "mode=\"disabled\"");
    let credentials = registry
        .execute(
            &CommandContext::default(),
            "proxy.credentials.set",
            json!({ "xml": plaintext, "id": 1, "username": "bob", "password": "new-secret" }),
        )
        .unwrap();
    assert_eq!(credentials["has_username"], true);
    assert_eq!(credentials["has_password"], true);
    assert!(credentials.get("username").is_none());
    assert!(credentials.get("password").is_none());
}

#[test]
fn chain_lifecycle_and_member_commands_preserve_order_and_references() {
    let registry = proxsep_command::CommandRegistry::standard();
    assert!(registry.len() >= 107);
    let xml = profile_with_chain();

    let kinds = registry
        .execute(&CommandContext::default(), "chain.kind.list", json!({}))
        .unwrap();
    assert_eq!(kinds, json!(["simple", "redundancy", "load_balancing"]));

    let created = registry
        .execute(
            &CommandContext::default(),
            "chain.create",
            json!({ "xml": xml, "name": "New Chain", "kind": "simple", "proxy_ids": [1] }),
        )
        .unwrap();
    assert_eq!(created["chain"]["id"], 3);
    let duplicated = registry
        .execute(
            &CommandContext::default(),
            "chain.duplicate",
            json!({ "xml": xml, "id": 10 }),
        )
        .unwrap();
    assert_eq!(duplicated["chain"]["id"], 3);
    assert_eq!(duplicated["chain"]["name"], "Main Chain Copy");

    let removed = registry
        .execute(
            &CommandContext::default(),
            "chain.member.remove",
            json!({ "xml": xml, "id": 10, "proxy_id": 2 }),
        )
        .unwrap();
    assert_eq!(removed["chain"]["proxy_ids"], json!([1]));
    let added = registry
        .execute(
            &CommandContext::default(),
            "chain.member.add",
            json!({ "xml": removed["xml"], "id": 10, "proxy_id": 2, "position": 0 }),
        )
        .unwrap();
    assert_eq!(added["chain"]["proxy_ids"], json!([2, 1]));
    let disabled = registry
        .execute(
            &CommandContext::default(),
            "chain.member.disable",
            json!({ "xml": added["xml"], "id": 10, "proxy_id": 2 }),
        )
        .unwrap();
    assert_eq!(disabled["chain"]["disabled_proxy_ids"], json!([2]));
    let enabled = registry
        .execute(
            &CommandContext::default(),
            "chain.member.enable",
            json!({ "xml": disabled["xml"], "id": 10, "proxy_id": 2 }),
        )
        .unwrap();
    assert_eq!(enabled["chain"]["disabled_proxy_ids"], json!([]));
    let moved = registry
        .execute(
            &CommandContext::default(),
            "chain.member.move",
            json!({ "xml": enabled["xml"], "id": 10, "from_index": 0, "to_index": 1 }),
        )
        .unwrap();
    assert_eq!(moved["chain"]["proxy_ids"], json!([1, 2]));

    let deleted = registry
        .execute(
            &CommandContext::default(),
            "chain.delete",
            json!({ "xml": xml, "id": 10 }),
        )
        .unwrap();
    assert_eq!(deleted["deleted"]["id"], 10);

    let referenced_xml = xml.replacen(
        "<Action type=\"Direct\" />",
        "<Action type=\"Chain\">10</Action>",
        1,
    );
    let referenced = registry.execute_request(
        &CommandContext::default(),
        CommandRequest {
            request_id: None,
            command: "chain.delete".into(),
            arguments: json!({ "xml": referenced_xml, "id": 10 }),
        },
    );
    assert_eq!(referenced.error.unwrap().code, "conflict");
}

#[test]
fn rule_catalog_exposes_real_inventory_field_and_action_commands() {
    let registry = proxsep_command::CommandRegistry::standard();
    assert!(registry.len() >= 142);
    let expected = [
        "rule.list",
        "rule.get",
        "rule.count",
        "rule.field.list",
        "rule.enabled.get",
        "rule.enabled.set",
        "rule.name.get",
        "rule.name.set",
        "rule.applications.get",
        "rule.applications.set",
        "rule.targets.get",
        "rule.targets.set",
        "rule.ports.get",
        "rule.ports.set",
        "rule.action.get",
        "rule.action.set",
        "rule.interface_id.get",
        "rule.interface_id.set",
        "rule.skip_if_interface_down.get",
        "rule.skip_if_interface_down.set",
        "rule.action.kind.list",
        "rule.create",
        "rule.delete",
        "rule.duplicate",
        "rule.move",
        "rule.enable",
        "rule.disable",
        "rule.priority.first",
        "rule.priority.last",
        "rule.priority.up",
        "rule.priority.down",
        "rule.action.direct",
        "rule.action.block",
        "rule.action.proxy",
        "rule.action.chain",
    ];
    for id in expected {
        assert!(registry.descriptor(id).is_some(), "missing {id}");
    }

    let fields = registry
        .execute(&CommandContext::default(), "rule.field.list", json!({}))
        .unwrap();
    assert_eq!(fields.as_array().unwrap().len(), 8);
    assert_eq!(fields[0]["field"], "enabled");
    assert_eq!(fields[7]["field"], "skip_if_interface_down");

    let kinds = registry
        .execute(
            &CommandContext::default(),
            "rule.action.kind.list",
            json!({}),
        )
        .unwrap();
    assert_eq!(kinds, json!(["direct", "block", "proxy", "chain"]));

    let xml = include_str!("../../proxsep-core/tests/fixtures/default.ppx");
    let fetched = registry
        .execute(
            &CommandContext::default(),
            "rule.get",
            json!({ "xml": xml, "index": 0 }),
        )
        .unwrap();
    assert_eq!(fetched["name"], "Localhost");
    assert_eq!(fetched["index"], 0);
    let count = registry
        .execute(
            &CommandContext::default(),
            "rule.count",
            json!({ "xml": xml }),
        )
        .unwrap();
    assert_eq!(
        count,
        json!({ "count": 2, "custom_count": 1, "default_index": 1 })
    );
}

#[test]
fn every_rule_field_round_trips_through_validated_profile_xml() {
    let registry = proxsep_command::CommandRegistry::standard();
    let xml = profile_with_chain();
    let cases = [
        ("enabled", json!(false)),
        ("name", json!("Web Browsers")),
        ("applications", json!("browser.exe; helper.exe")),
        ("targets", json!("example.com; *.internal")),
        ("ports", json!("80; 443; 8000-8100")),
        ("action", json!({ "kind": "proxy", "id": 1 })),
        ("interface_id", json!("ethernet-1")),
        ("skip_if_interface_down", json!(true)),
    ];

    for (field, replacement) in cases {
        let get_id = format!("rule.{field}.get");
        let set_id = format!("rule.{field}.set");
        assert!(registry.descriptor(&get_id).is_some(), "missing {get_id}");
        assert!(registry.descriptor(&set_id).is_some(), "missing {set_id}");

        let changed = registry
            .execute(
                &CommandContext::default(),
                &set_id,
                json!({ "xml": xml, "index": 0, "value": replacement }),
            )
            .unwrap();
        let read = registry
            .execute(
                &CommandContext::default(),
                &get_id,
                json!({ "xml": changed["xml"], "index": 0 }),
            )
            .unwrap();
        assert_eq!(read["value"], replacement, "{set_id} did not persist");
    }

    for field in ["applications", "targets", "ports"] {
        let changed = registry
            .execute(
                &CommandContext::default(),
                &format!("rule.{field}.set"),
                json!({ "xml": xml, "index": 0, "value": "Any" }),
            )
            .unwrap();
        assert_eq!(changed["value"], "");
    }
}

#[test]
fn rule_lifecycle_preserves_the_default_fallback_and_custom_order() {
    let registry = proxsep_command::CommandRegistry::standard();
    let base = profile_with_chain();
    let created = registry
        .execute(
            &CommandContext::default(),
            "rule.create",
            json!({
                "xml": base,
                "name": "Web",
                "applications": "browser.exe",
                "action": { "kind": "block" }
            }),
        )
        .unwrap();
    assert_eq!(created["rule"]["index"], 1);
    assert_eq!(created["rule"]["name"], "Web");

    let created_xml = created["xml"].as_str().unwrap();
    let listed = registry
        .execute(
            &CommandContext::default(),
            "rule.list",
            json!({ "xml": created_xml }),
        )
        .unwrap();
    assert_eq!(listed.as_array().unwrap().len(), 3);
    assert_eq!(listed[0]["name"], "Localhost");
    assert_eq!(listed[1]["name"], "Web");
    assert_eq!(listed[2]["name"], "Default");

    let duplicated = registry
        .execute(
            &CommandContext::default(),
            "rule.duplicate",
            json!({ "xml": created_xml, "index": 1 }),
        )
        .unwrap();
    assert_eq!(duplicated["rule"]["index"], 2);
    assert_eq!(duplicated["rule"]["name"], "Copy of Web");

    let disabled = registry
        .execute(
            &CommandContext::default(),
            "rule.disable",
            json!({ "xml": duplicated["xml"], "index": 1 }),
        )
        .unwrap();
    assert_eq!(disabled["rule"]["enabled"], false);
    let enabled = registry
        .execute(
            &CommandContext::default(),
            "rule.enable",
            json!({ "xml": disabled["xml"], "index": 1 }),
        )
        .unwrap();
    assert_eq!(enabled["rule"]["enabled"], true);

    let moved = registry
        .execute(
            &CommandContext::default(),
            "rule.move",
            json!({ "xml": enabled["xml"], "from_index": 2, "to_index": 0 }),
        )
        .unwrap();
    assert_eq!(moved["rule"]["index"], 0);
    assert_eq!(moved["rule"]["name"], "Copy of Web");

    let deleted = registry
        .execute(
            &CommandContext::default(),
            "rule.delete",
            json!({ "xml": moved["xml"], "index": 0 }),
        )
        .unwrap();
    assert_eq!(deleted["deleted"]["name"], "Copy of Web");
    let after_delete = registry
        .execute(
            &CommandContext::default(),
            "rule.list",
            json!({ "xml": deleted["xml"] }),
        )
        .unwrap();
    assert_eq!(after_delete[2]["name"], "Default");

    for command in ["rule.delete", "rule.duplicate", "rule.disable"] {
        let response = registry.execute_request(
            &CommandContext::default(),
            CommandRequest {
                request_id: None,
                command: command.into(),
                arguments: json!({ "xml": deleted["xml"], "index": 2 }),
            },
        );
        assert_eq!(response.error.unwrap().code, "conflict", "{command}");
    }

    let reserved_name = registry.execute_request(
        &CommandContext::default(),
        CommandRequest {
            request_id: None,
            command: "rule.create".into(),
            arguments: json!({
                "xml": base,
                "name": "Default",
                "action": { "kind": "direct" }
            }),
        },
    );
    assert_eq!(reserved_name.error.unwrap().code, "conflict");
}

#[test]
fn rule_priority_commands_never_move_the_default_rule() {
    let registry = proxsep_command::CommandRegistry::standard();
    let base = include_str!("../../proxsep-core/tests/fixtures/default.ppx");
    let a = registry
        .execute(
            &CommandContext::default(),
            "rule.create",
            json!({ "xml": base, "name": "A", "action": { "kind": "direct" } }),
        )
        .unwrap();
    let b = registry
        .execute(
            &CommandContext::default(),
            "rule.create",
            json!({ "xml": a["xml"], "name": "B", "action": { "kind": "direct" } }),
        )
        .unwrap();

    let first = registry
        .execute(
            &CommandContext::default(),
            "rule.priority.first",
            json!({ "xml": b["xml"], "index": 2 }),
        )
        .unwrap();
    assert_eq!(first["rule"]["index"], 0);
    let last = registry
        .execute(
            &CommandContext::default(),
            "rule.priority.last",
            json!({ "xml": first["xml"], "index": 0 }),
        )
        .unwrap();
    assert_eq!(last["rule"]["index"], 2);
    let up = registry
        .execute(
            &CommandContext::default(),
            "rule.priority.up",
            json!({ "xml": last["xml"], "index": 2 }),
        )
        .unwrap();
    assert_eq!(up["rule"]["index"], 1);
    let down = registry
        .execute(
            &CommandContext::default(),
            "rule.priority.down",
            json!({ "xml": up["xml"], "index": 1 }),
        )
        .unwrap();
    assert_eq!(down["rule"]["index"], 2);

    let listed = registry
        .execute(
            &CommandContext::default(),
            "rule.list",
            json!({ "xml": down["xml"] }),
        )
        .unwrap();
    assert_eq!(listed[3]["name"], "Default");

    for (command, index) in [("rule.priority.up", 0), ("rule.priority.down", 2)] {
        let response = registry.execute_request(
            &CommandContext::default(),
            CommandRequest {
                request_id: None,
                command: command.into(),
                arguments: json!({ "xml": down["xml"], "index": index }),
            },
        );
        assert_eq!(response.error.unwrap().code, "conflict", "{command}");
    }
}

#[test]
fn rule_action_commands_validate_references_and_allow_default_action_edits() {
    let registry = proxsep_command::CommandRegistry::standard();
    let xml = profile_with_chain();
    let cases = [
        (
            "rule.action.direct",
            json!({ "xml": xml, "index": 0 }),
            json!({ "kind": "direct" }),
        ),
        (
            "rule.action.block",
            json!({ "xml": xml, "index": 0 }),
            json!({ "kind": "block" }),
        ),
        (
            "rule.action.proxy",
            json!({ "xml": xml, "index": 0, "proxy_id": 1 }),
            json!({ "kind": "proxy", "id": 1 }),
        ),
        (
            "rule.action.chain",
            json!({ "xml": xml, "index": 0, "chain_id": 10 }),
            json!({ "kind": "chain", "id": 10 }),
        ),
    ];
    for (command, arguments, expected) in cases {
        let changed = registry
            .execute(&CommandContext::default(), command, arguments)
            .unwrap();
        assert_eq!(changed["rule"]["action"], expected, "{command}");
    }

    let default_changed = registry
        .execute(
            &CommandContext::default(),
            "rule.action.block",
            json!({ "xml": xml, "index": 1 }),
        )
        .unwrap();
    assert_eq!(default_changed["rule"]["name"], "Default");
    assert_eq!(
        default_changed["rule"]["action"],
        json!({ "kind": "block" })
    );

    let forbidden_default_edit = registry.execute_request(
        &CommandContext::default(),
        CommandRequest {
            request_id: None,
            command: "rule.name.set".into(),
            arguments: json!({ "xml": xml, "index": 1, "value": "Fallback" }),
        },
    );
    assert_eq!(forbidden_default_edit.error.unwrap().code, "conflict");

    for (command, arguments) in [
        (
            "rule.action.proxy",
            json!({ "xml": xml, "index": 0, "proxy_id": 99 }),
        ),
        (
            "rule.action.chain",
            json!({ "xml": xml, "index": 0, "chain_id": 99 }),
        ),
    ] {
        let response = registry.execute_request(
            &CommandContext::default(),
            CommandRequest {
                request_id: None,
                command: command.into(),
                arguments,
            },
        );
        assert_eq!(response.error.unwrap().code, "not_found", "{command}");
    }
}

#[test]
fn rule_commands_reject_malformed_edits_and_out_of_range_indices() {
    let registry = proxsep_command::CommandRegistry::standard();
    let xml = profile_with_chain();
    let cases = [
        (
            "rule.ports.set",
            json!({ "xml": xml, "index": 0, "value": "443-bad" }),
            "invalid_arguments",
        ),
        (
            "rule.action.proxy",
            json!({ "xml": xml, "index": 0, "proxy_id": 0 }),
            "invalid_arguments",
        ),
        (
            "rule.action.chain",
            json!({ "xml": xml, "index": 0, "chain_id": 0 }),
            "invalid_arguments",
        ),
        (
            "rule.enabled.set",
            json!({ "xml": xml, "index": 1, "value": false }),
            "conflict",
        ),
        (
            "rule.move",
            json!({ "xml": xml, "from_index": 1, "to_index": 0 }),
            "conflict",
        ),
        ("rule.get", json!({ "xml": xml, "index": 99 }), "not_found"),
        (
            "rule.create",
            json!({ "xml": xml, "name": "   ", "action": { "kind": "direct" } }),
            "invalid_arguments",
        ),
        (
            "rule.action.set",
            json!({ "xml": xml, "index": 0, "value": { "kind": "direct", "id": 1 } }),
            "invalid_arguments",
        ),
        (
            "rule.get",
            json!({ "xml": xml, "index": 0, "unexpected": true }),
            "invalid_arguments",
        ),
    ];
    for (command, arguments, expected_code) in cases {
        let response = registry.execute_request(
            &CommandContext::default(),
            CommandRequest {
                request_id: None,
                command: command.into(),
                arguments,
            },
        );
        assert_eq!(
            response.error.unwrap().code,
            expected_code,
            "{command} returned the wrong error"
        );
    }
}
