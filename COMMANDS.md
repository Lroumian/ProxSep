# ProxSep Command Architecture

ProxSep uses one command registry for every control surface. Business logic must
not be independently reimplemented in the desktop UI, CLI, JSON automation, or
MCP server.

```text
Desktop UI ----\
CLI -----------+--> CommandRegistry --> Core / Runtime / Driver / Service
JSON Lines ----+          |
MCP stdio -----/          +--> descriptor + JSON Schema + risk + handler
```

## Contract

Every registered command has:

- a stable lowercase dotted ID and integer contract version;
- a project domain and concise user-visible summary;
- a risk class: `read_only`, `mutating`, or `disruptive`;
- an input and output JSON Schema;
- one implementation shared by UI, CLI, JSON, and MCP;
- contract tests for discovery, malformed input, structured errors, and behavior.

The JSON request envelope is:

```json
{
  "request_id": "caller-selected-id",
  "command": "route.trace",
  "arguments": {}
}
```

Responses preserve `request_id` and `command`, and contain either `result` or a
stable error `code`. A malformed envelope returns `invalid_request`; an unknown
ID returns `unknown_command`.

## Adapters

- `proxsep command list|describe|invoke|stream` exposes discovery and JSON Lines.
- `proxsep-mcp` maps every descriptor to an MCP tool through `tools/list` and
  executes it through `tools/call`.
- The desktop app owns the same registry and is migrating actions away from
  direct runtime calls. New UI actions must start as commands.
- MCP and JSON are local stdio adapters by default. Network listeners require a
  separate authenticated transport and are not implicitly enabled.

## 500+ command target

The target catalog is organized by project concepts, not aliases. The count is
an implementation target; only commands with a working handler are registered.

| Domain | Target | Examples |
|---|---:|---|
| profile and history | 56 | validate, import, export, diff, snapshot, rollback |
| options and credentials | 44 | inspect, protect, unlock, rotate, compatibility |
| proxies and health | 64 | CRUD, test phases, metrics, failure policy |
| chains and selection | 48 | topology, members, failover, affinity, simulation |
| rules and temporary policy | 72 | CRUD, order, trace, groups, expiry, simulation |
| connections and timeline | 72 | list, inspect, filter, export, kill, reroute, events |
| processes and process trees | 48 | identity, lineage, descendants, filters, rules |
| DNS and correlation | 56 | policy, cache, fake IP, query/response, flow links |
| interfaces and routing | 32 | enumerate, bind, state, fallback, route probes |
| driver and transparent mode | 48 | status, counters, lifecycle, events, diagnostics |
| service and jobs | 36 | lifecycle, configuration, task status, cancellation |
| system, catalog, diagnostics | 32 | discovery, schema, capabilities, support bundle |
| **Total target** | **608** | Each item requires implementation and tests. |

Catalog growth is verified with `system.command.count`. Planned or unsupported
operations are documented but are never registered as working commands.

## Current command families

The implemented catalog includes discovery, PPX validation/summary/normalizing,
all modeled profile-option reads and validated writes, credential-safe proxy
inventory and lifecycle operations, proxy endpoints and credential state,
proxy-chain inventory/lifecycle/member ordering and field editing, reference
analysis, route decision/trace, process lineage, retained/active connections,
history cleanup, failure reset, runtime profile replacement, and DNS
observation/reverse fake-IP lookup. The registry is the authoritative source
for the exact current count; documentation must not hard-code it as if the
608-command target were already complete.
