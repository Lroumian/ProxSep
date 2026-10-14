//! Shared command contract for desktop, CLI, JSON, and MCP adapters.

use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use proxsep_core::{
    profile::{Action, Profile},
    rules::{Connection, RuleEngine},
};
use proxsep_runtime::Runtime;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandSurface {
    Ui,
    Cli,
    Json,
    Mcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandRisk {
    ReadOnly,
    Mutating,
    Disruptive,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommandDescriptor {
    pub id: String,
    pub version: u32,
    pub domain: String,
    pub summary: String,
    pub risk: CommandRisk,
    pub surfaces: Vec<CommandSurface>,
    pub input_schema: Value,
    pub output_schema: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandRequest {
    pub request_id: Option<String>,
    pub command: String,
    #[serde(default = "empty_object")]
    pub arguments: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommandFailure {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CommandResponse {
    pub request_id: Option<String>,
    pub command: String,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<CommandFailure>,
}

#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    #[error("unknown command: {0}")]
    Unknown(String),
    #[error("invalid arguments: {0}")]
    InvalidArguments(String),
    #[error("command requires a live runtime")]
    RuntimeRequired,
    #[error("command failed: {0}")]
    Failed(String),
}

#[derive(Clone, Default)]
pub struct CommandContext {
    pub runtime: Option<Arc<Runtime>>,
}

type Handler = fn(&CommandRegistry, &CommandContext, Value) -> Result<Value, CommandError>;

struct RegisteredCommand {
    descriptor: CommandDescriptor,
    handler: Handler,
}

pub struct CommandRegistry {
    commands: BTreeMap<String, RegisteredCommand>,
}

impl CommandRegistry {
    pub fn standard() -> Self {
        let mut registry = Self {
            commands: BTreeMap::new(),
        };
        registry.register(
            descriptor(
                "system.command.list",
                "system",
                "List every registered command",
                CommandRisk::ReadOnly,
                empty_schema(),
                schema("array"),
            ),
            command_list,
        );
        registry.register(
            descriptor(
                "system.command.describe",
                "system",
                "Describe one command and its JSON contract",
                CommandRisk::ReadOnly,
                required_string_schema("id"),
                schema("object"),
            ),
            command_describe,
        );
        registry.register(
            descriptor(
                "system.command.count",
                "system",
                "Count registered commands by domain and risk",
                CommandRisk::ReadOnly,
                empty_schema(),
                schema("object"),
            ),
            command_count,
        );
        registry.register(
            descriptor(
                "profile.validate",
                "profile",
                "Validate a PPX profile for the current Windows user",
                CommandRisk::ReadOnly,
                required_string_schema("xml"),
                schema("object"),
            ),
            profile_validate,
        );
        registry.register(
            descriptor(
                "profile.summary",
                "profile",
                "Return a credential-safe PPX profile summary",
                CommandRisk::ReadOnly,
                required_string_schema("xml"),
                schema("object"),
            ),
            profile_summary,
        );
        registry.register(
            descriptor(
                "profile.normalize",
                "profile",
                "Parse, validate, and serialize a PPX profile",
                CommandRisk::ReadOnly,
                required_string_schema("xml"),
                schema("object"),
            ),
            profile_normalize,
        );
        registry.register(
            descriptor(
                "route.decide",
                "route",
                "Evaluate the winning rule for a connection",
                CommandRisk::ReadOnly,
                route_schema(),
                schema("object"),
            ),
            route_decide,
        );
        registry.register(
            descriptor(
                "route.trace",
                "route",
                "Explain every rule condition for a connection",
                CommandRisk::ReadOnly,
                route_schema(),
                schema("object"),
            ),
            route_trace,
        );
        registry.register(
            descriptor(
                "process.lineage.get",
                "process",
                "Read a root-first Windows process lineage",
                CommandRisk::ReadOnly,
                required_integer_schema("pid"),
                schema("object"),
            ),
            process_lineage,
        );
        registry.register(
            descriptor(
                "process.lineage.current",
                "process",
                "Read the current ProxSep process lineage",
                CommandRisk::ReadOnly,
                empty_schema(),
                schema("object"),
            ),
            process_current_lineage,
        );
        registry.register(
            descriptor(
                "runtime.connection.list",
                "runtime",
                "List retained connection events",
                CommandRisk::ReadOnly,
                empty_schema(),
                schema("array"),
            ),
            runtime_connections,
        );
        registry.register(
            descriptor(
                "runtime.connection.active_list",
                "runtime",
                "List active connection events",
                CommandRisk::ReadOnly,
                empty_schema(),
                schema("array"),
            ),
            runtime_active_connections,
        );
        registry.register(
            descriptor(
                "runtime.connection.history_clear",
                "runtime",
                "Remove completed connection history while preserving live flows",
                CommandRisk::Mutating,
                empty_schema(),
                schema("object"),
            ),
            runtime_clear_history,
        );
        registry.register(
            descriptor(
                "runtime.failure.reset",
                "runtime",
                "Reset proxy failure and affinity state",
                CommandRisk::Mutating,
                empty_schema(),
                schema("object"),
            ),
            runtime_reset_failures,
        );
        registry.register(
            descriptor(
                "runtime.profile.replace",
                "runtime",
                "Validate and apply a PPX profile to new connections",
                CommandRisk::Mutating,
                required_string_schema("xml"),
                schema("object"),
            ),
            runtime_replace_profile,
        );
        registry.register(
            descriptor(
                "dns.fake.reverse",
                "dns",
                "Resolve a retained fake IPv4 address back to its hostname",
                CommandRisk::ReadOnly,
                required_string_schema("ip"),
                schema("object"),
            ),
            dns_fake_reverse,
        );
        registry.register(
            descriptor(
                "dns.local.observe",
                "dns",
                "Update automatic local-DNS availability observation",
                CommandRisk::Mutating,
                required_boolean_schema("available"),
                schema("object"),
            ),
            dns_local_observe,
        );
        registry
    }

    pub fn len(&self) -> usize {
        self.commands.len()
    }

    pub fn is_empty(&self) -> bool {
        self.commands.is_empty()
    }

    pub fn descriptors(&self) -> Vec<CommandDescriptor> {
        self.commands
            .values()
            .map(|command| command.descriptor.clone())
            .collect()
    }

    pub fn descriptor(&self, id: &str) -> Option<&CommandDescriptor> {
        self.commands.get(id).map(|command| &command.descriptor)
    }

    pub fn execute(
        &self,
        context: &CommandContext,
        id: &str,
        arguments: Value,
    ) -> Result<Value, CommandError> {
        let command = self
            .commands
            .get(id)
            .ok_or_else(|| CommandError::Unknown(id.into()))?;
        (command.handler)(self, context, arguments)
    }

    pub fn execute_request(
        &self,
        context: &CommandContext,
        request: CommandRequest,
    ) -> CommandResponse {
        let result = self.execute(context, &request.command, request.arguments);
        match result {
            Ok(value) => CommandResponse {
                request_id: request.request_id,
                command: request.command,
                ok: true,
                result: Some(value),
                error: None,
            },
            Err(error) => CommandResponse {
                request_id: request.request_id,
                command: request.command,
                ok: false,
                result: None,
                error: Some(CommandFailure {
                    code: match &error {
                        CommandError::Unknown(_) => "unknown_command",
                        CommandError::InvalidArguments(_) => "invalid_arguments",
                        CommandError::RuntimeRequired => "runtime_required",
                        CommandError::Failed(_) => "command_failed",
                    }
                    .into(),
                    message: error.to_string(),
                    details: None,
                }),
            },
        }
    }

    pub fn execute_json(&self, context: &CommandContext, request: &str) -> CommandResponse {
        match serde_json::from_str::<CommandRequest>(request) {
            Ok(request) => self.execute_request(context, request),
            Err(error) => CommandResponse {
                request_id: None,
                command: String::new(),
                ok: false,
                result: None,
                error: Some(CommandFailure {
                    code: "invalid_request".into(),
                    message: format!("invalid command request: {error}"),
                    details: None,
                }),
            },
        }
    }

    fn register(&mut self, descriptor: CommandDescriptor, handler: Handler) {
        let id = descriptor.id.clone();
        assert!(
            self.commands
                .insert(
                    id.clone(),
                    RegisteredCommand {
                        descriptor,
                        handler,
                    },
                )
                .is_none(),
            "duplicate command ID: {id}"
        );
    }
}

fn descriptor(
    id: &str,
    domain: &str,
    summary: &str,
    risk: CommandRisk,
    input_schema: Value,
    output_schema: Value,
) -> CommandDescriptor {
    CommandDescriptor {
        id: id.into(),
        version: 1,
        domain: domain.into(),
        summary: summary.into(),
        risk,
        surfaces: vec![
            CommandSurface::Ui,
            CommandSurface::Cli,
            CommandSurface::Json,
            CommandSurface::Mcp,
        ],
        input_schema,
        output_schema,
    }
}

fn schema(kind: &str) -> Value {
    json!({ "type": kind })
}

fn empty_schema() -> Value {
    json!({ "type": "object", "additionalProperties": false })
}

fn required_string_schema(field: &str) -> Value {
    json!({
        "type": "object",
        "required": [field],
        "properties": { (field): { "type": "string" } },
        "additionalProperties": false
    })
}

fn required_integer_schema(field: &str) -> Value {
    json!({
        "type": "object",
        "required": [field],
        "properties": { (field): { "type": "integer", "minimum": 1 } },
        "additionalProperties": false
    })
}

fn required_boolean_schema(field: &str) -> Value {
    json!({
        "type": "object",
        "required": [field],
        "properties": { (field): { "type": "boolean" } },
        "additionalProperties": false
    })
}

fn route_schema() -> Value {
    json!({
        "type": "object",
        "required": ["xml", "application", "target", "port"],
        "properties": {
            "xml": { "type": "string" },
            "application": { "type": "string" },
            "target": { "type": "string" },
            "port": { "type": "integer", "minimum": 1, "maximum": 65535 },
            "pid": { "type": ["integer", "null"], "minimum": 1 },
            "resolved_ips": { "type": "array", "items": { "type": "string", "format": "ip" } },
            "interfaces": { "type": "object" }
        },
        "additionalProperties": false
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EmptyArguments {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdArguments {
    id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileArguments {
    xml: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteArguments {
    xml: String,
    application: String,
    target: String,
    port: u16,
    #[serde(default)]
    pid: Option<u32>,
    #[serde(default)]
    resolved_ips: Vec<IpAddr>,
    #[serde(default)]
    interfaces: HashMap<String, Vec<IpAddr>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PidArguments {
    pid: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IpArguments {
    ip: Ipv4Addr,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AvailabilityArguments {
    available: bool,
}

fn arguments<T: DeserializeOwned>(value: Value) -> Result<T, CommandError> {
    serde_json::from_value(value).map_err(|error| CommandError::InvalidArguments(error.to_string()))
}

fn empty_object() -> Value {
    json!({})
}

fn no_arguments(value: Value) -> Result<(), CommandError> {
    let _: EmptyArguments = arguments(value)?;
    Ok(())
}

fn profile(xml: &str) -> Result<Profile, CommandError> {
    Profile::from_xml_for_current_user(xml).map_err(|error| CommandError::Failed(error.to_string()))
}

fn runtime(context: &CommandContext) -> Result<&Runtime, CommandError> {
    context
        .runtime
        .as_deref()
        .ok_or(CommandError::RuntimeRequired)
}

fn command_list(
    registry: &CommandRegistry,
    _: &CommandContext,
    value: Value,
) -> Result<Value, CommandError> {
    no_arguments(value)?;
    serde_json::to_value(registry.descriptors())
        .map_err(|error| CommandError::Failed(error.to_string()))
}

fn command_describe(
    registry: &CommandRegistry,
    _: &CommandContext,
    value: Value,
) -> Result<Value, CommandError> {
    let input: IdArguments = arguments(value)?;
    let descriptor = registry
        .descriptor(&input.id)
        .ok_or(CommandError::Unknown(input.id))?;
    serde_json::to_value(descriptor).map_err(|error| CommandError::Failed(error.to_string()))
}

fn command_count(
    registry: &CommandRegistry,
    _: &CommandContext,
    value: Value,
) -> Result<Value, CommandError> {
    no_arguments(value)?;
    let mut domains = BTreeMap::<&str, usize>::new();
    for command in registry.commands.values() {
        *domains.entry(&command.descriptor.domain).or_default() += 1;
    }
    Ok(json!({ "total": registry.len(), "domains": domains }))
}

fn profile_validate(
    _: &CommandRegistry,
    _: &CommandContext,
    value: Value,
) -> Result<Value, CommandError> {
    let input: ProfileArguments = arguments(value)?;
    profile(&input.xml)?
        .validate()
        .map_err(|error| CommandError::Failed(error.to_string()))?;
    Ok(json!({ "valid": true }))
}

fn profile_summary(
    _: &CommandRegistry,
    _: &CommandContext,
    value: Value,
) -> Result<Value, CommandError> {
    let input: ProfileArguments = arguments(value)?;
    let profile = profile(&input.xml)?;
    profile
        .validate()
        .map_err(|error| CommandError::Failed(error.to_string()))?;
    Ok(json!({
        "version": profile.version,
        "platform": profile.platform,
        "proxies": profile.proxies.len(),
        "chains": profile.chains.len(),
        "rules": profile.rules.len(),
        "credential_state": format!("{:?}", profile.credential_state),
        "encryption_mode": profile.options.encryption_mode
    }))
}

fn profile_normalize(
    _: &CommandRegistry,
    _: &CommandContext,
    value: Value,
) -> Result<Value, CommandError> {
    let input: ProfileArguments = arguments(value)?;
    let profile = profile(&input.xml)?;
    profile
        .validate()
        .map_err(|error| CommandError::Failed(error.to_string()))?;
    let xml = profile
        .to_xml()
        .map_err(|error| CommandError::Failed(error.to_string()))?;
    Ok(json!({ "xml": xml }))
}

fn connection(input: RouteArguments) -> Result<(Profile, Connection), CommandError> {
    if input.port == 0 {
        return Err(CommandError::InvalidArguments(
            "port must be non-zero".into(),
        ));
    }
    let profile = profile(&input.xml)?;
    profile
        .validate()
        .map_err(|error| CommandError::Failed(error.to_string()))?;
    let mut connection = Connection::new(input.application, input.target, input.port);
    connection.pid = input.pid;
    connection.resolved_ips = input.resolved_ips;
    connection.interfaces = input.interfaces;
    Ok((profile, connection))
}

fn action(action: &Action) -> String {
    match action {
        Action::Direct => "direct".into(),
        Action::Block => "block".into(),
        Action::Proxy(id) => format!("proxy:{id}"),
        Action::Chain(id) => format!("chain:{id}"),
    }
}

fn route_decide(
    _: &CommandRegistry,
    _: &CommandContext,
    value: Value,
) -> Result<Value, CommandError> {
    let (profile, connection) = connection(arguments(value)?)?;
    let decision = RuleEngine::new(&profile.rules).decide(&connection);
    Ok(json!({
        "rule": decision.rule_name,
        "action": action(decision.action),
        "interface": decision.interface_id
    }))
}

fn route_trace(
    _: &CommandRegistry,
    _: &CommandContext,
    value: Value,
) -> Result<Value, CommandError> {
    let (profile, connection) = connection(arguments(value)?)?;
    let trace = RuleEngine::new(&profile.rules).trace(&connection);
    let text = trace.render_text(&connection);
    let rules = trace
        .rules
        .iter()
        .map(|rule| {
            json!({
                "index": rule.index,
                "name": rule.rule_name,
                "outcome": rule.outcome.label(),
                "conditions": rule.conditions.iter().map(|condition| json!({
                    "kind": condition.kind.label(),
                    "matched": condition.matched,
                    "expected": condition.expected,
                    "actual": condition.actual
                })).collect::<Vec<_>>()
            })
        })
        .collect::<Vec<_>>();
    Ok(json!({
        "decision": {
            "rule": trace.decision.rule_name,
            "action": action(trace.decision.action),
            "interface": trace.decision.interface_id
        },
        "rules": rules,
        "text": text
    }))
}

fn lineage_value(pid: u32) -> Result<Value, CommandError> {
    let lineage = proxsep_runtime::windows::process_lineage(pid)
        .map_err(|error| CommandError::Failed(error.to_string()))?;
    Ok(json!({
        "pid": pid,
        "lineage": lineage.iter().map(|process| json!({
            "pid": process.pid,
            "parent_pid": process.parent_pid,
            "executable": process.executable,
            "path": process.path,
            "started_at_unix_ms": process.started_at.and_then(|started| started.duration_since(std::time::UNIX_EPOCH).ok()).map(|duration| duration.as_millis())
        })).collect::<Vec<_>>()
    }))
}

fn process_lineage(
    _: &CommandRegistry,
    _: &CommandContext,
    value: Value,
) -> Result<Value, CommandError> {
    let input: PidArguments = arguments(value)?;
    if input.pid == 0 {
        return Err(CommandError::InvalidArguments(
            "pid must be non-zero".into(),
        ));
    }
    lineage_value(input.pid)
}

fn process_current_lineage(
    _: &CommandRegistry,
    _: &CommandContext,
    value: Value,
) -> Result<Value, CommandError> {
    no_arguments(value)?;
    lineage_value(std::process::id())
}

fn event_value(event: proxsep_runtime::ConnectionEvent) -> Value {
    json!({
        "id": event.id,
        "protocol": event.protocol,
        "application": event.application,
        "pid": event.pid,
        "target": event.target,
        "port": event.port,
        "resolved_ips": event.resolved_ips.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "destination": event.destination.map(|value| value.to_string()),
        "interface": event.interface_id,
        "bind_ips": event.bind_ips.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "rule": event.rule,
        "action": event.action,
        "state": event.state,
        "sent": event.sent,
        "received": event.received,
        "error": event.error,
        "duration_ms": event.duration().map(|duration| duration.as_millis())
    })
}

fn runtime_connections(
    _: &CommandRegistry,
    context: &CommandContext,
    value: Value,
) -> Result<Value, CommandError> {
    no_arguments(value)?;
    Ok(Value::Array(
        runtime(context)?
            .events()
            .into_iter()
            .map(event_value)
            .collect(),
    ))
}

fn runtime_active_connections(
    _: &CommandRegistry,
    context: &CommandContext,
    value: Value,
) -> Result<Value, CommandError> {
    no_arguments(value)?;
    Ok(Value::Array(
        runtime(context)?
            .active_connections()
            .into_iter()
            .map(event_value)
            .collect(),
    ))
}

fn runtime_clear_history(
    _: &CommandRegistry,
    context: &CommandContext,
    value: Value,
) -> Result<Value, CommandError> {
    no_arguments(value)?;
    let runtime = runtime(context)?;
    let before = runtime.events().len();
    runtime.clear_events();
    Ok(json!({ "removed": before.saturating_sub(runtime.events().len()) }))
}

fn runtime_reset_failures(
    _: &CommandRegistry,
    context: &CommandContext,
    value: Value,
) -> Result<Value, CommandError> {
    no_arguments(value)?;
    runtime(context)?.reset_failures();
    Ok(json!({ "reset": true }))
}

fn runtime_replace_profile(
    _: &CommandRegistry,
    context: &CommandContext,
    value: Value,
) -> Result<Value, CommandError> {
    let input: ProfileArguments = arguments(value)?;
    runtime(context)?
        .replace_profile(profile(&input.xml)?)
        .map_err(|error| CommandError::Failed(error.to_string()))?;
    Ok(json!({ "applied": true }))
}

fn dns_fake_reverse(
    _: &CommandRegistry,
    context: &CommandContext,
    value: Value,
) -> Result<Value, CommandError> {
    let input: IpArguments = arguments(value)?;
    Ok(json!({
        "ip": input.ip,
        "hostname": runtime(context)?.original_hostname(input.ip)
    }))
}

fn dns_local_observe(
    _: &CommandRegistry,
    context: &CommandContext,
    value: Value,
) -> Result<Value, CommandError> {
    let input: AvailabilityArguments = arguments(value)?;
    runtime(context)?.observe_local_dns(input.available);
    Ok(json!({ "available": input.available }))
}
