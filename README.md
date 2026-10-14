# ProxSep

<p align="center">
  <strong>English</strong> | <a href="./README.zh-CN.md">简体中文</a>
</p>

<p align="center">
  <strong>A Rust-native Windows proxy router and traffic policy engine for developers, reverse engineers, and power users.</strong>
</p>

<p align="center">
  Program-level routing · SOCKS/HTTP proxying · rule debugging · DNS correlation · Windows Service · WFP driver
</p>

<p align="center">
  <img alt="Rust" src="https://img.shields.io/badge/Rust-2024-orange?logo=rust">
  <img alt="Platform" src="https://img.shields.io/badge/platform-Windows-0078D6?logo=windows">
  <img alt="License" src="https://img.shields.io/badge/license-GPL--3.0--or--later-blue">
  <img alt="Status" src="https://img.shields.io/badge/status-experimental-yellow">
</p>

---

> [!WARNING]
> ProxSep is under active development. The WFP driver builds, but is not yet signed, installed, or considered deployment-ready. Do not treat a successful build as proof that transparent proxying is production-safe.

## Why ProxSep?

ProxSep is not intended to be a pixel-for-pixel clone of another product. It is an independent Rust implementation focused on **programmable routing, observability, and transparent Windows networking**.

The long-term goal is to make it easy to answer:

- Which process created this connection?
- Which rule matched, and why?
- Where is this traffic being routed?
- Which DNS resolution produced this destination?
- Can the route be changed without restarting the application?
- Can the same routing engine be controlled from a desktop UI, CLI, service, or API?

Packet inspection is intentionally out of scope for the core project. Dedicated packet-analysis tooling can integrate with ProxSep later.

## Current capabilities

### Routing & rules

- Ordered rules with a Default fallback.
- Match by executable path, filename, PID, destination, IPv4 CIDR, dual-stack ranges, port ranges, and interface.
- Rule decision traces with per-condition expected/actual evidence in the desktop diagnostics and CLI.
- Hot configuration reload.
- Direct / proxy routing primitives.
- Transparent TCP routing path backed by WFP context and records.

### Proxy protocols

- SOCKS4 / SOCKS4A / SOCKS5.
- HTTP CONNECT.
- HTTP Basic authentication.
- Windows SSPI NTLM / Negotiate.
- Serial proxy chains.
- Redundancy / failover.
- Random load balancing with PID stickiness.

### DNS & identity

- Dedicated DNS listener.
- Stable `127.8.0.0/16` fake-address mapping.
- Windows TCP-table process attribution for the local SOCKS entry.
- WFP-provided target and identity data for transparent connections.

### Tooling

- Native desktop profile editor.
- CLI for validation, rule evaluation, serving, and transparent mode.
- Windows Service / console daemon.
- Live connection view with active/history filtering, lifecycle state, byte counters, route context, and per-connection rule traces.
- Shared schema-backed command registry used by the desktop, CLI, JSON Lines, and stdio MCP adapters; see [command architecture](COMMANDS.md).
- Proxy connectivity checks.
- PPX v100–102 import/write support, including nested authentication, Windows account-bound DPAPI credentials, chains, DNS/interface configuration, and preservation of unknown extension fields.

## Not finished yet

The following areas are intentionally tracked as incomplete:

- Kernel DNS datagram capture/injection and full system-DNS integration.
- UDP policy and routing.
- HTTP-only request forwarding.
- PPX Basic and master-password credential decrypt/generation (Windows account-bound DPAPI mode is supported).
- Continuous background health checks.
- Manual startup overrides.
- Service / other-user / leak-prevention policy.
- System-level behavioral validation.
- Signed and packaged WFP driver deployment.

## Architecture

```text
Desktop UI ─┐
CLI        ──┼────> ProxSep Core / Rule Engine
Service    ──┘               │
                              ├── Proxy protocols
                              ├── DNS tracker
                              ├── Runtime / flow manager
                              └── Windows platform layer
                                         │
                                         └── WFP driver
```

Workspace layout:

```text
crates/
  proxsep-core       configuration, rules, DNS
  proxsep-protocol   proxy protocols and SSPI
  proxsep-runtime    routing, listeners, Windows queries
  proxsep-driver     user-mode driver protocol
  proxsep-desktop    native desktop UI
  proxsep-service    Windows Service / daemon
  proxsep-cli        command-line interface

drivers/
  proxsep-wfp        independent Rust WDM/WFP driver
```

## Build

Requirements:

- Rust toolchain with Edition 2024 support.
- Windows.
- WDK only when building the kernel driver.

Validation:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo check --workspace --all-targets
cargo test --workspace
cargo build --workspace --release
.\scripts\build-driver.ps1
```

The driver build script **does not** install the driver or modify test-signing / Secure Boot settings.

## Usage

Open a profile in the desktop editor:

```powershell
cargo run -p proxsep-desktop -- 'C:\Profiles\Profile.ppx'
```

Validate a profile:

```powershell
cargo run -p proxsep-cli -- check-profile 'C:\Profiles\Profile.ppx'
```

Evaluate a route:

```powershell
cargo run -p proxsep-cli -- route 'C:\Profiles\Profile.ppx' --app app.exe --host example.com --port 443
```

Explain every evaluated rule and condition, with optional process, DNS, and interface context:

```powershell
cargo run -p proxsep-cli -- route 'C:\Profiles\Profile.ppx' --app Wardogs.exe --host api.example.com --port 443 --pid 8432 --resolved-ip 34.120.1.8 --interface Ethernet --interface-ip 192.0.2.10 --trace
```

Start the local proxy entry:

```powershell
cargo run -p proxsep-cli -- serve 'C:\Profiles\Profile.ppx' --listen 127.0.0.1:1081
```

Optional DNS listener:

```powershell
cargo run -p proxsep-cli -- serve 'C:\Profiles\Profile.ppx' --dns-listen 127.0.0.1:5353 --dns-upstream 127.0.0.1:53
```

Transparent mode, only after deploying the ProxSep driver yourself:

```powershell
cargo run -p proxsep-cli -- transparent 'C:\Profiles\Profile.ppx'
```

The local SOCKS entry attempts to identify the real PID/application from Windows TCP tables. An explicit `--app` value is only a user-supplied label and is not trusted kernel identity.

The transparent listener only accepts sockets backed by ProxSep WFP context/records; ordinary connections cannot self-declare their target or identity.

## Roadmap

### v0.1 — Foundation

- [x] Rust workspace.
- [x] PPX parsing/writing.
- [x] Ordered rule engine.
- [x] SOCKS4/4A/5.
- [x] HTTP CONNECT.
- [x] Proxy chains, failover, and load balancing.
- [x] Desktop editor.
- [x] CLI and Windows Service.
- [x] Experimental WFP driver path.

### v0.2 — Observable routing

- [x] Rule decision trace: explain exactly why a rule matched.
- [x] Live Connections with lifecycle, traffic counters, route context, and selection details.
- [ ] Process tree and richer process identity.
- [ ] DNS-to-flow correlation.
- [ ] Connection timeline.
- [ ] Improved proxy health metrics.
- [ ] Rule creation from live connections.

### v0.3 — UDP & automation

- [ ] UDP routing model.
- [ ] QUIC-aware flow metadata.
- [ ] REST API.
- [ ] WebSocket event stream.
- [x] Shared UI / CLI / JSON / MCP command foundation.
- [ ] Dynamic policy and failover conditions.
- [ ] Scriptable / machine-readable rule diagnostics.

### Later

- [ ] Separate packet-analysis companion.
- [ ] Flow-to-PCAP handoff.
- [ ] Plugin / extension API.
- [ ] Signed driver packaging and installer.

## Clean-room / compatibility policy

ProxSep is independently developed.

The project does **not** reuse proprietary source code, icons, branding, or private assets from third-party products. Compatibility work should be based on public behavior, public formats, and independently observed interoperability requirements.

"ProxSep" is its own project and is not affiliated with Proxifier or Initex.

## Contributing

Issues, implementation discussions, documentation fixes, and focused pull requests are welcome.

Before contributing, read [CONTRIBUTING.md](CONTRIBUTING.md). Security-sensitive findings should follow [SECURITY.md](SECURITY.md) instead of being opened publicly.

## License

ProxSep is licensed under **GPL-3.0-or-later**.

You may use, modify, redistribute, and sell copies of the software. If you distribute a modified version based on GPL-covered ProxSep code, the corresponding source must remain available under the GPL terms.

See [LICENSE](LICENSE) for the complete license text.
