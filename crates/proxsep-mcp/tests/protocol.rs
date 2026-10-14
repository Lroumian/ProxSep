use proxsep_command::{CommandContext, CommandRegistry};
use proxsep_mcp::McpServer;
use serde_json::json;

fn server() -> McpServer {
    McpServer::new(CommandRegistry::standard(), CommandContext::default())
}

#[test]
fn initialize_and_tool_discovery_follow_json_rpc_envelopes() {
    let server = server();
    let initialized = server
        .handle(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        }))
        .unwrap();
    assert_eq!(initialized["result"]["serverInfo"]["name"], "proxsep");
    assert_eq!(
        initialized["result"]["capabilities"]["tools"]["listChanged"],
        false
    );

    let tools = server
        .handle(json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" }))
        .unwrap();
    assert!(tools["result"]["tools"].as_array().unwrap().len() >= 12);
    assert!(
        tools["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .all(|tool| { tool["inputSchema"].is_object() && tool["outputSchema"].is_object() })
    );
}

#[test]
fn tool_calls_use_the_shared_registry_and_return_structured_content() {
    let response = server()
        .handle(json!({
            "jsonrpc": "2.0",
            "id": "count",
            "method": "tools/call",
            "params": { "name": "system.command.count", "arguments": {} }
        }))
        .unwrap();
    assert_eq!(response["id"], "count");
    assert_eq!(response["result"]["isError"], false);
    assert!(
        response["result"]["structuredContent"]["total"]
            .as_u64()
            .unwrap()
            >= 12
    );

    let unknown = server()
        .handle(json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": { "name": "missing.command", "arguments": {} }
        }))
        .unwrap();
    assert_eq!(unknown["result"]["isError"], true);
}

#[test]
fn notifications_are_silent_and_malformed_json_gets_a_protocol_error() {
    assert!(
        server()
            .handle(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
            .is_none()
    );
    let malformed = server().handle_json("not json").unwrap();
    assert_eq!(malformed["error"]["code"], -32700);
}
