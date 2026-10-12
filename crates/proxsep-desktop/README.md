# Rust desktop frontend

Run from the workspace with `cargo run -p proxsep-desktop -- [profile.ppx]`.

The native window edits Proxifier `.ppx` profiles, proxy server credentials,
chain hops (sequential, redundancy, load balancing), ordered rules and DNS/options. Ctrl+O opens a profile and Ctrl+S
saves it. Closing, opening another profile or creating a new profile prompts
for unsaved changes. Referenced proxy deletion is rejected to keep rules and
chains valid. Password input is masked; saved profile credential storage follows
the core profile codec.

Profile saves write and flush a sibling temporary file before replacement, so a
failed write does not truncate the existing profile. Successful profile opening
applies the loaded profile to new runtime connections. Changes made in the
editor can be applied with **Apply profile**; existing tunnels retain their route.

Route diagnostics provides a static rule preview and a live test through the
full connection runtime (including DNS/interface context). The
checker opens a TCP connection and completes the selected proxy's tunnel
handshake to the configured target; success means tunnel establishment, not an
end-to-end application or TLS test.

The Connections tab starts/stops a loopback SOCKS5 listener and displays the
runtime's bounded connection-event store, byte counts, errors and rule decisions.
Filters and TSV export are available. The application identity entered for the
local listener takes precedence in application-name rules; it is not a kernel
identity. When the label is empty, the runtime attempts Windows TCP-table PID
and process-path lookup. Those snapshots can race process exit.

The DNS/options tab can start a local DNS listener with an explicit upstream DNS
endpoint. It does not alter operating-system DNS configuration. New profiles use
the original `disabled` credential-encryption enum; imported opaque encryption
modes are preserved and unsupported credentials produce explicit runtime errors.

This frontend has an independent native layout. Pixel-identical rendering and
OS-wide interception are not implied by the profile editor.
