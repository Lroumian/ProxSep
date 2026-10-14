//! Minimal stdio MCP adapter over the shared ProxSep command registry.

use proxsep_command::{CommandContext, CommandRegistry};
use serde_json::{Value, json};

pub struct McpServer {
    registry: CommandRegistry,
    context: CommandContext,
}

impl McpServer {
    pub fn new(registry: CommandRegistry, context: CommandContext) -> Self {
        Self { registry, context }
    }

    pub fn handle_json(&self, input: &str) -> Option<Value> {
        let request = match serde_json::from_str::<Value>(input) {
            Ok(request) => request,
            Err(error) => {
                return Some(error_response(
                    Value::Null,
                    -32700,
                    format!("parse error: {error}"),
                ));
            }
        };
        self.handle(request)
    }

    pub fn handle(&self, request: Value) -> Option<Value> {
        let object = match request.as_object() {
            Some(object) if request["jsonrpc"] == "2.0" => object,
            _ => {
                return Some(error_response(
                    request.get("id").cloned().unwrap_or(Value::Null),
                    -32600,
                    "invalid JSON-RPC request",
                ));
            }
        };
        let id = object.get("id").cloned();
        let method = object.get("method").and_then(Value::as_str).unwrap_or("");
        let params = object.get("params").cloned().unwrap_or_else(|| json!({}));
        let result = match method {
            "initialize" => Ok(json!({
                "protocolVersion": "2025-06-18",
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": { "name": "proxsep", "version": env!("CARGO_PKG_VERSION") },
                "instructions": "Every tool maps directly to the shared ProxSep command registry."
            })),
            "ping" => Ok(json!({})),
            "tools/list" => Ok(self.tools()),
            "tools/call" => self.call_tool(params),
            "notifications/initialized" | "notifications/cancelled" => return None,
            _ => Err((-32601, format!("method not found: {method}"))),
        };
        let id = id?;
        Some(match result {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            Err((code, message)) => error_response(id, code, message),
        })
    }

    fn tools(&self) -> Value {
        json!({
            "tools": self.registry
                .descriptors()
                .into_iter()
                .map(|command| {
                    let read_only = command.risk == proxsep_command::CommandRisk::ReadOnly;
                    let destructive = command.risk == proxsep_command::CommandRisk::Disruptive;
                    json!({
                        "name": command.id,
                        "title": command.summary,
                        "description": format!("{} command (v{}, domain: {})", command.summary, command.version, command.domain),
                        "inputSchema": command.input_schema,
                        "outputSchema": command.output_schema,
                        "annotations": {
                            "readOnlyHint": read_only,
                            "destructiveHint": destructive,
                            "idempotentHint": read_only,
                            "openWorldHint": false
                        }
                    })
                })
                .collect::<Vec<_>>()
        })
    }

    fn call_tool(&self, params: Value) -> Result<Value, (i64, String)> {
        let name = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| (-32602, "tools/call requires a string name".into()))?;
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        match self.registry.execute(&self.context, name, arguments) {
            Ok(result) => Ok(json!({
                "content": [{ "type": "text", "text": serde_json::to_string_pretty(&result).unwrap_or_else(|_| "null".into()) }],
                "structuredContent": result,
                "isError": false
            })),
            Err(error) => Ok(json!({
                "content": [{ "type": "text", "text": error.to_string() }],
                "isError": true
            })),
        }
    }
}

fn error_response(id: Value, code: i64, message: impl Into<String>) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message.into() }
    })
}
