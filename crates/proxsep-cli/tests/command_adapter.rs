use std::process::Command;

#[test]
fn json_invoke_returns_a_machine_readable_shared_command_response() {
    let output = Command::new(env!("CARGO_BIN_EXE_proxsep"))
        .args([
            "command",
            "invoke",
            r#"{"request_id":"cli-test","command":"system.command.count","arguments":{}}"#,
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["request_id"], "cli-test");
    assert_eq!(response["command"], "system.command.count");
    assert_eq!(response["ok"], true);
    assert!(response["result"]["total"].as_u64().unwrap() >= 12);
}

#[test]
fn json_invoke_keeps_protocol_errors_in_stdout() {
    let output = Command::new(env!("CARGO_BIN_EXE_proxsep"))
        .args(["command", "invoke", "not-json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let response: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["ok"], false);
    assert_eq!(response["error"]["code"], "invalid_request");
}
