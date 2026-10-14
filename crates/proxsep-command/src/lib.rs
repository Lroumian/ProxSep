//! Shared command contract for desktop, CLI, JSON, and MCP adapters.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use proxsep_core::{
    profile::{Action, CredentialState, Profile},
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
    #[error("not found: {0}")]
    NotFound(String),
    #[error("command failed: {0}")]
    Failed(String),
}

#[derive(Clone, Default)]
pub struct CommandContext {
    pub runtime: Option<Arc<Runtime>>,
}

type Handler = fn(&CommandRegistry, &CommandContext, Value) -> Result<Value, CommandError>;

#[derive(Debug, Clone, Copy)]
enum ProfileOptionField {
    ResolveAutoModeDetection,
    ResolveViaProxy,
    ResolveBlockNonATypes,
    ResolveExclusionList,
    ResolveExclusionOnlyFromList,
    ResolveDnsUdpMode,
    EncryptionMode,
    ConnectionLoopDetection,
    ConnectionLoopResolve,
    UdpMode,
    LeakPrevention,
    ProcessOtherUsers,
    ProcessServices,
    HandleDirectConnections,
    HttpProxiesSupport,
}

const PROFILE_OPTION_FIELDS: [ProfileOptionField; 15] = [
    ProfileOptionField::ResolveAutoModeDetection,
    ProfileOptionField::ResolveViaProxy,
    ProfileOptionField::ResolveBlockNonATypes,
    ProfileOptionField::ResolveExclusionList,
    ProfileOptionField::ResolveExclusionOnlyFromList,
    ProfileOptionField::ResolveDnsUdpMode,
    ProfileOptionField::EncryptionMode,
    ProfileOptionField::ConnectionLoopDetection,
    ProfileOptionField::ConnectionLoopResolve,
    ProfileOptionField::UdpMode,
    ProfileOptionField::LeakPrevention,
    ProfileOptionField::ProcessOtherUsers,
    ProfileOptionField::ProcessServices,
    ProfileOptionField::HandleDirectConnections,
    ProfileOptionField::HttpProxiesSupport,
];

#[derive(Debug, Clone, Copy)]
enum ProxyField {
    Protocol,
    Address,
    Port,
    Label,
    UserAgent,
    Options,
}

const PROXY_FIELDS: [ProxyField; 6] = [
    ProxyField::Protocol,
    ProxyField::Address,
    ProxyField::Port,
    ProxyField::Label,
    ProxyField::UserAgent,
    ProxyField::Options,
];

impl ProxyField {
    fn id(self) -> &'static str {
        match self {
            Self::Protocol => "protocol",
            Self::Address => "address",
            Self::Port => "port",
            Self::Label => "label",
            Self::UserAgent => "user_agent",
            Self::Options => "options",
        }
    }

    fn value_schema(self) -> Value {
        match self {
            Self::Protocol => json!({
                "type": "string",
                "enum": ["SOCKS4", "SOCKS4A", "SOCKS5", "HTTPS", "HTTP"]
            }),
            Self::Port => json!({ "type": "integer", "minimum": 1, "maximum": 65535 }),
            Self::Options => json!({ "type": "integer", "minimum": 0, "maximum": 4294967295_u64 }),
            _ => json!({ "type": "string" }),
        }
    }

    fn value(self, proxy: &proxsep_core::profile::Proxy) -> Value {
        match self {
            Self::Protocol => json!(proxy.protocol),
            Self::Address => json!(proxy.address),
            Self::Port => json!(proxy.port),
            Self::Label => json!(proxy.label),
            Self::UserAgent => json!(proxy.user_agent),
            Self::Options => json!(proxy.options),
        }
    }

    fn set(
        self,
        proxy: &mut proxsep_core::profile::Proxy,
        value: Value,
    ) -> Result<(), CommandError> {
        let invalid_type = || {
            CommandError::InvalidArguments(format!(
                "value for proxy.{} has the wrong type or range",
                self.id()
            ))
        };
        match self {
            Self::Protocol => {
                let protocol = value.as_str().ok_or_else(invalid_type)?;
                if !["SOCKS4", "SOCKS4A", "SOCKS5", "HTTPS", "HTTP"].contains(&protocol) {
                    return Err(invalid_type());
                }
                proxy.protocol = protocol.to_owned();
            }
            Self::Address => proxy.address = value.as_str().ok_or_else(invalid_type)?.to_owned(),
            Self::Port => {
                proxy.port = value
                    .as_u64()
                    .and_then(|value| u16::try_from(value).ok())
                    .filter(|value| *value != 0)
                    .ok_or_else(invalid_type)?
            }
            Self::Label => proxy.label = value.as_str().ok_or_else(invalid_type)?.to_owned(),
            Self::UserAgent => {
                proxy.user_agent = value.as_str().ok_or_else(invalid_type)?.to_owned()
            }
            Self::Options => {
                proxy.options = value
                    .as_u64()
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or_else(invalid_type)?
            }
        }
        Ok(())
    }
}

impl ProfileOptionField {
    fn id(self) -> &'static str {
        match self {
            Self::ResolveAutoModeDetection => "resolve.auto_mode_detection",
            Self::ResolveViaProxy => "resolve.via_proxy",
            Self::ResolveBlockNonATypes => "resolve.block_non_a_types",
            Self::ResolveExclusionList => "resolve.exclusion_list",
            Self::ResolveExclusionOnlyFromList => "resolve.exclusion_only_from_list",
            Self::ResolveDnsUdpMode => "resolve.dns_udp_mode",
            Self::EncryptionMode => "encryption_mode",
            Self::ConnectionLoopDetection => "connection_loop_detection",
            Self::ConnectionLoopResolve => "connection_loop_resolve",
            Self::UdpMode => "udp_mode",
            Self::LeakPrevention => "leak_prevention",
            Self::ProcessOtherUsers => "process_other_users",
            Self::ProcessServices => "process_services",
            Self::HandleDirectConnections => "handle_direct_connections",
            Self::HttpProxiesSupport => "http_proxies_support",
        }
    }

    fn value_schema(self) -> Value {
        match self {
            Self::ResolveExclusionList => json!({ "type": "string" }),
            Self::ResolveDnsUdpMode => {
                json!({ "type": "integer", "minimum": 0, "maximum": 255 })
            }
            Self::EncryptionMode => json!({
                "type": "string",
                "enum": ["disabled", "account", "basic", "master"]
            }),
            Self::UdpMode => json!({
                "type": "string",
                "enum": ["mode_bypass", "mode_block_443", "mode_block_all"]
            }),
            _ => json!({ "type": "boolean" }),
        }
    }

    fn value(self, profile: &Profile) -> Value {
        let options = &profile.options;
        match self {
            Self::ResolveAutoModeDetection => json!(options.resolve.auto_mode_detection),
            Self::ResolveViaProxy => json!(options.resolve.via_proxy),
            Self::ResolveBlockNonATypes => json!(options.resolve.block_non_a_types),
            Self::ResolveExclusionList => json!(options.resolve.exclusion_list),
            Self::ResolveExclusionOnlyFromList => {
                json!(options.resolve.exclusion_only_from_list)
            }
            Self::ResolveDnsUdpMode => json!(options.resolve.dns_udp_mode),
            Self::EncryptionMode => json!(options.encryption_mode),
            Self::ConnectionLoopDetection => json!(options.connection_loop_detection),
            Self::ConnectionLoopResolve => json!(options.connection_loop_resolve),
            Self::UdpMode => json!(options.udp_mode),
            Self::LeakPrevention => json!(options.leak_prevention),
            Self::ProcessOtherUsers => json!(options.process_other_users),
            Self::ProcessServices => json!(options.process_services),
            Self::HandleDirectConnections => json!(options.handle_direct_connections),
            Self::HttpProxiesSupport => json!(options.http_proxies_support),
        }
    }

    fn set(self, profile: &mut Profile, value: Value) -> Result<(), CommandError> {
        let invalid_type = || {
            CommandError::InvalidArguments(format!(
                "value for options.{} has the wrong type or range",
                self.id()
            ))
        };
        match self {
            Self::ResolveAutoModeDetection => {
                profile.options.resolve.auto_mode_detection =
                    value.as_bool().ok_or_else(invalid_type)?
            }
            Self::ResolveViaProxy => {
                profile.options.resolve.via_proxy = value.as_bool().ok_or_else(invalid_type)?
            }
            Self::ResolveBlockNonATypes => {
                profile.options.resolve.block_non_a_types =
                    value.as_bool().ok_or_else(invalid_type)?
            }
            Self::ResolveExclusionList => {
                profile.options.resolve.exclusion_list =
                    value.as_str().ok_or_else(invalid_type)?.to_owned()
            }
            Self::ResolveExclusionOnlyFromList => {
                profile.options.resolve.exclusion_only_from_list =
                    value.as_bool().ok_or_else(invalid_type)?
            }
            Self::ResolveDnsUdpMode => {
                profile.options.resolve.dns_udp_mode = value
                    .as_u64()
                    .and_then(|value| u8::try_from(value).ok())
                    .ok_or_else(invalid_type)?
            }
            Self::EncryptionMode => {
                set_encryption_mode(profile, value.as_str().ok_or_else(invalid_type)?)?
            }
            Self::ConnectionLoopDetection => {
                profile.options.connection_loop_detection =
                    value.as_bool().ok_or_else(invalid_type)?
            }
            Self::ConnectionLoopResolve => {
                profile.options.connection_loop_resolve =
                    value.as_bool().ok_or_else(invalid_type)?
            }
            Self::UdpMode => {
                let mode = value.as_str().ok_or_else(invalid_type)?;
                if !["mode_bypass", "mode_block_443", "mode_block_all"].contains(&mode) {
                    return Err(invalid_type());
                }
                profile.options.udp_mode = mode.to_owned();
            }
            Self::LeakPrevention => {
                profile.options.leak_prevention = value.as_bool().ok_or_else(invalid_type)?
            }
            Self::ProcessOtherUsers => {
                profile.options.process_other_users = value.as_bool().ok_or_else(invalid_type)?
            }
            Self::ProcessServices => {
                profile.options.process_services = value.as_bool().ok_or_else(invalid_type)?
            }
            Self::HandleDirectConnections => {
                profile.options.handle_direct_connections =
                    value.as_bool().ok_or_else(invalid_type)?
            }
            Self::HttpProxiesSupport => {
                profile.options.http_proxies_support = value.as_bool().ok_or_else(invalid_type)?
            }
        }
        Ok(())
    }
}

enum CommandHandler {
    Function(Handler),
    ProfileOptionGet(ProfileOptionField),
    ProfileOptionSet(ProfileOptionField),
    ProxyFieldGet(ProxyField),
    ProxyFieldSet(ProxyField),
}

struct RegisteredCommand {
    descriptor: CommandDescriptor,
    handler: CommandHandler,
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
                "options.get",
                "options",
                "Read all non-secret PPX profile options",
                CommandRisk::ReadOnly,
                required_string_schema("xml"),
                schema("object"),
            ),
            options_get,
        );
        registry.register(
            descriptor(
                "options.field.list",
                "options",
                "List editable PPX option fields and value schemas",
                CommandRisk::ReadOnly,
                empty_schema(),
                schema("array"),
            ),
            options_field_list,
        );
        for field in PROFILE_OPTION_FIELDS {
            let get_id = format!("options.{}.get", field.id());
            let set_id = format!("options.{}.set", field.id());
            registry.register_handler(
                descriptor(
                    &get_id,
                    "options",
                    &format!("Read PPX option {}", field.id()),
                    CommandRisk::ReadOnly,
                    required_string_schema("xml"),
                    profile_option_output_schema(field),
                ),
                CommandHandler::ProfileOptionGet(field),
            );
            registry.register_handler(
                descriptor(
                    &set_id,
                    "options",
                    &format!("Set PPX option {} and return validated XML", field.id()),
                    CommandRisk::Mutating,
                    profile_option_set_schema(field),
                    profile_option_set_output_schema(field),
                ),
                CommandHandler::ProfileOptionSet(field),
            );
        }
        for (id, summary, handler) in [
            (
                "proxy.list",
                "List proxies without exposing credential values",
                proxy_list as Handler,
            ),
            (
                "proxy.get",
                "Read one proxy without exposing credential values",
                proxy_get as Handler,
            ),
            (
                "proxy.count",
                "Count configured proxies",
                proxy_count as Handler,
            ),
            (
                "proxy.id.next",
                "Find the first available positive proxy identifier",
                proxy_next_id as Handler,
            ),
            (
                "proxy.references",
                "List chains and rules that reference a proxy",
                proxy_references as Handler,
            ),
        ] {
            let input_schema = match id {
                "proxy.get" | "proxy.references" => profile_id_schema(),
                _ => required_string_schema("xml"),
            };
            registry.register(
                descriptor(
                    id,
                    "proxy",
                    summary,
                    CommandRisk::ReadOnly,
                    input_schema,
                    schema(if id == "proxy.list" {
                        "array"
                    } else {
                        "object"
                    }),
                ),
                handler,
            );
        }
        for field in PROXY_FIELDS {
            let get_id = format!("proxy.{}.get", field.id());
            let set_id = format!("proxy.{}.set", field.id());
            registry.register_handler(
                descriptor(
                    &get_id,
                    "proxy",
                    &format!("Read proxy field {}", field.id()),
                    CommandRisk::ReadOnly,
                    profile_id_schema(),
                    proxy_field_output_schema(field, false),
                ),
                CommandHandler::ProxyFieldGet(field),
            );
            registry.register_handler(
                descriptor(
                    &set_id,
                    "proxy",
                    &format!("Set proxy field {} and return validated XML", field.id()),
                    CommandRisk::Mutating,
                    proxy_field_set_schema(field),
                    proxy_field_output_schema(field, true),
                ),
                CommandHandler::ProxyFieldSet(field),
            );
        }
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
        match &command.handler {
            CommandHandler::Function(handler) => handler(self, context, arguments),
            CommandHandler::ProfileOptionGet(field) => profile_option_get(*field, arguments),
            CommandHandler::ProfileOptionSet(field) => profile_option_set(*field, arguments),
            CommandHandler::ProxyFieldGet(field) => proxy_field_get(*field, arguments),
            CommandHandler::ProxyFieldSet(field) => proxy_field_set(*field, arguments),
        }
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
                        CommandError::NotFound(_) => "not_found",
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
        self.register_handler(descriptor, CommandHandler::Function(handler));
    }

    fn register_handler(&mut self, descriptor: CommandDescriptor, handler: CommandHandler) {
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

fn profile_option_set_schema(field: ProfileOptionField) -> Value {
    json!({
        "type": "object",
        "required": ["xml", "value"],
        "properties": {
            "xml": { "type": "string" },
            "value": field.value_schema()
        },
        "additionalProperties": false
    })
}

fn profile_option_output_schema(field: ProfileOptionField) -> Value {
    json!({
        "type": "object",
        "required": ["field", "value"],
        "properties": {
            "field": { "type": "string", "const": field.id() },
            "value": field.value_schema()
        },
        "additionalProperties": false
    })
}

fn profile_option_set_output_schema(field: ProfileOptionField) -> Value {
    json!({
        "type": "object",
        "required": ["field", "value", "xml"],
        "properties": {
            "field": { "type": "string", "const": field.id() },
            "value": field.value_schema(),
            "xml": { "type": "string" }
        },
        "additionalProperties": false
    })
}

fn profile_id_schema() -> Value {
    json!({
        "type": "object",
        "required": ["xml", "id"],
        "properties": {
            "xml": { "type": "string" },
            "id": { "type": "integer", "minimum": 1, "maximum": 4294967295_u64 }
        },
        "additionalProperties": false
    })
}

fn proxy_field_set_schema(field: ProxyField) -> Value {
    json!({
        "type": "object",
        "required": ["xml", "id", "value"],
        "properties": {
            "xml": { "type": "string" },
            "id": { "type": "integer", "minimum": 1, "maximum": 4294967295_u64 },
            "value": field.value_schema()
        },
        "additionalProperties": false
    })
}

fn proxy_field_output_schema(field: ProxyField, include_xml: bool) -> Value {
    let mut required = vec![json!("id"), json!("field"), json!("value")];
    let mut properties = serde_json::Map::from_iter([
        ("id".into(), json!({ "type": "integer" })),
        (
            "field".into(),
            json!({ "type": "string", "const": field.id() }),
        ),
        ("value".into(), field.value_schema()),
    ]);
    if include_xml {
        required.push(json!("xml"));
        properties.insert("xml".into(), json!({ "type": "string" }));
    }
    json!({
        "type": "object",
        "required": required,
        "properties": properties,
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
struct ProfileOptionSetArguments {
    xml: String,
    value: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileIdArguments {
    xml: String,
    id: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileIdValueArguments {
    xml: String,
    id: u32,
    value: Value,
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
    let mut risks = BTreeMap::<&str, usize>::new();
    for command in registry.commands.values() {
        *domains.entry(&command.descriptor.domain).or_default() += 1;
        let risk = match command.descriptor.risk {
            CommandRisk::ReadOnly => "read_only",
            CommandRisk::Mutating => "mutating",
            CommandRisk::Disruptive => "disruptive",
        };
        *risks.entry(risk).or_default() += 1;
    }
    for risk in ["read_only", "mutating", "disruptive"] {
        risks.entry(risk).or_default();
    }
    Ok(json!({ "total": registry.len(), "domains": domains, "risks": risks }))
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

fn options_value(profile: &Profile) -> Value {
    let options = &profile.options;
    json!({
        "resolve": {
            "auto_mode_detection": options.resolve.auto_mode_detection,
            "via_proxy": options.resolve.via_proxy,
            "block_non_a_types": options.resolve.block_non_a_types,
            "exclusion_list": options.resolve.exclusion_list,
            "exclusion_only_from_list": options.resolve.exclusion_only_from_list,
            "dns_udp_mode": options.resolve.dns_udp_mode
        },
        "encryption_mode": options.encryption_mode,
        "connection_loop_detection": options.connection_loop_detection,
        "connection_loop_resolve": options.connection_loop_resolve,
        "udp_mode": options.udp_mode,
        "leak_prevention": options.leak_prevention,
        "process_other_users": options.process_other_users,
        "process_services": options.process_services,
        "handle_direct_connections": options.handle_direct_connections,
        "http_proxies_support": options.http_proxies_support
    })
}

fn options_get(
    _: &CommandRegistry,
    _: &CommandContext,
    value: Value,
) -> Result<Value, CommandError> {
    let input: ProfileArguments = arguments(value)?;
    Ok(options_value(&profile(&input.xml)?))
}

fn options_field_list(
    _: &CommandRegistry,
    _: &CommandContext,
    value: Value,
) -> Result<Value, CommandError> {
    no_arguments(value)?;
    Ok(Value::Array(
        PROFILE_OPTION_FIELDS
            .into_iter()
            .map(|field| {
                json!({
                    "field": field.id(),
                    "value_schema": field.value_schema(),
                    "get_command": format!("options.{}.get", field.id()),
                    "set_command": format!("options.{}.set", field.id())
                })
            })
            .collect(),
    ))
}

fn profile_option_get(field: ProfileOptionField, value: Value) -> Result<Value, CommandError> {
    let input: ProfileArguments = arguments(value)?;
    let profile = profile(&input.xml)?;
    Ok(json!({ "field": field.id(), "value": field.value(&profile) }))
}

fn profile_option_set(field: ProfileOptionField, value: Value) -> Result<Value, CommandError> {
    let input: ProfileOptionSetArguments = arguments(value)?;
    let mut profile = profile(&input.xml)?;
    field.set(&mut profile, input.value)?;
    let value = field.value(&profile);
    let xml = profile
        .to_xml()
        .map_err(|error| CommandError::Failed(error.to_string()))?;
    Ok(json!({ "field": field.id(), "value": value, "xml": xml }))
}

fn set_encryption_mode(profile: &mut Profile, mode: &str) -> Result<(), CommandError> {
    if profile.options.encryption_mode.eq_ignore_ascii_case(mode) {
        return Ok(());
    }
    match mode {
        "account" => profile
            .enable_account_protection()
            .map_err(|error| CommandError::Failed(error.to_string())),
        "disabled" => {
            for proxy in &profile.proxies {
                if profile
                    .password_is_protected(proxy)
                    .map_err(|error| CommandError::Failed(error.to_string()))?
                {
                    return Err(CommandError::Failed(
                        "unlock or replace opaque credentials before disabling encryption".into(),
                    ));
                }
            }
            profile.options.encryption_mode = "disabled".into();
            profile.credential_state = CredentialState::Plaintext;
            Ok(())
        }
        "basic" | "master" => Err(CommandError::Failed(format!(
            "creating {mode} credential protection is not supported; imported values are preserved"
        ))),
        _ => Err(CommandError::InvalidArguments(format!(
            "unsupported encryption mode: {mode}"
        ))),
    }
}

fn profile_with_id(value: Value) -> Result<(Profile, u32), CommandError> {
    let input: ProfileIdArguments = arguments(value)?;
    if input.id == 0 {
        return Err(CommandError::InvalidArguments(
            "proxy ID must be non-zero".into(),
        ));
    }
    Ok((profile(&input.xml)?, input.id))
}

fn proxy_value(proxy: &proxsep_core::profile::Proxy) -> Value {
    json!({
        "id": proxy.id,
        "protocol": proxy.protocol,
        "address": proxy.address,
        "port": proxy.port,
        "label": proxy.label,
        "user_agent": proxy.user_agent,
        "options": proxy.options,
        "has_username": proxy.username.as_deref().is_some_and(|value| !value.is_empty()),
        "has_password": proxy.password.as_deref().is_some_and(|value| !value.is_empty())
    })
}

fn proxy_list(
    _: &CommandRegistry,
    _: &CommandContext,
    value: Value,
) -> Result<Value, CommandError> {
    let input: ProfileArguments = arguments(value)?;
    Ok(Value::Array(
        profile(&input.xml)?
            .proxies
            .iter()
            .map(proxy_value)
            .collect(),
    ))
}

fn proxy_get(_: &CommandRegistry, _: &CommandContext, value: Value) -> Result<Value, CommandError> {
    let (profile, id) = profile_with_id(value)?;
    profile
        .proxies
        .iter()
        .find(|proxy| proxy.id == id)
        .map(proxy_value)
        .ok_or_else(|| CommandError::NotFound(format!("proxy {id}")))
}

fn proxy_count(
    _: &CommandRegistry,
    _: &CommandContext,
    value: Value,
) -> Result<Value, CommandError> {
    let input: ProfileArguments = arguments(value)?;
    Ok(json!({ "count": profile(&input.xml)?.proxies.len() }))
}

fn proxy_next_id(
    _: &CommandRegistry,
    _: &CommandContext,
    value: Value,
) -> Result<Value, CommandError> {
    let input: ProfileArguments = arguments(value)?;
    let profile = profile(&input.xml)?;
    let existing = profile
        .proxies
        .iter()
        .map(|proxy| proxy.id)
        .collect::<HashSet<_>>();
    let id = (1..u32::MAX)
        .find(|id| !existing.contains(id))
        .ok_or_else(|| CommandError::Failed("no proxy identifier is available".into()))?;
    Ok(json!({ "id": id }))
}

fn proxy_references(
    _: &CommandRegistry,
    _: &CommandContext,
    value: Value,
) -> Result<Value, CommandError> {
    let (profile, id) = profile_with_id(value)?;
    if !profile.proxies.iter().any(|proxy| proxy.id == id) {
        return Err(CommandError::NotFound(format!("proxy {id}")));
    }
    let chains = profile
        .chains
        .iter()
        .filter(|chain| chain.proxy_ids.contains(&id))
        .map(|chain| json!({ "id": chain.id, "name": chain.name }))
        .collect::<Vec<_>>();
    let rules = profile
        .rules
        .iter()
        .enumerate()
        .filter(|(_, rule)| {
            matches!(&rule.action, Action::Proxy(action_id) if action_id.parse::<u32>().ok() == Some(id))
        })
        .map(|(index, rule)| json!({ "index": index, "name": rule.name }))
        .collect::<Vec<_>>();
    Ok(json!({ "id": id, "chains": chains, "rules": rules }))
}

fn proxy_field_get(field: ProxyField, value: Value) -> Result<Value, CommandError> {
    let (profile, id) = profile_with_id(value)?;
    let proxy = profile
        .proxies
        .iter()
        .find(|proxy| proxy.id == id)
        .ok_or_else(|| CommandError::NotFound(format!("proxy {id}")))?;
    Ok(json!({ "id": id, "field": field.id(), "value": field.value(proxy) }))
}

fn proxy_field_set(field: ProxyField, value: Value) -> Result<Value, CommandError> {
    let input: ProfileIdValueArguments = arguments(value)?;
    if input.id == 0 {
        return Err(CommandError::InvalidArguments(
            "proxy ID must be non-zero".into(),
        ));
    }
    let mut profile = profile(&input.xml)?;
    let proxy = profile
        .proxies
        .iter_mut()
        .find(|proxy| proxy.id == input.id)
        .ok_or_else(|| CommandError::NotFound(format!("proxy {}", input.id)))?;
    field.set(proxy, input.value)?;
    let value = field.value(proxy);
    let xml = profile
        .to_xml()
        .map_err(|error| CommandError::Failed(error.to_string()))?;
    Ok(json!({ "id": input.id, "field": field.id(), "value": value, "xml": xml }))
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
