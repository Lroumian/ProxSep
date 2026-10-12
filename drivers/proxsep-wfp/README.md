# Independent Rust WFP driver (development, unsigned)

This is independently written Rust using documented WDK/WFP DDIs. It is **not a
complete or binary-compatible Proxifier driver replacement**. No original driver
code, disassembly, or analysis report is included here. The separate workspace keeps kernel build flags
out of the application workspace.

## Build and validation

From the application repository, run `scripts/build-driver.ps1`. The script uses
an existing WDK and libclang, changes environment only inside its process, builds
the native x64 image, and copies the private output to
`target/x86_64-pc-windows-msvc/release/proxsep-wfp.sys`. It does not sign, install,
load, change boot settings, or modify the original driver. Parameters select
existing WDK/libclang locations. WDK 10.0.26100.0, MSVC 14.44.35207 and Rust
1.99.0 have produced the image locally. Lockfile pins build dependencies.

Validation performed: eight pure-policy unit tests and two deterministic
callback/response barrier integration tests, formatting, Clippy with
warnings denied for policy and kernel crate, release link, and `dumpbin` PE
headers/imports inspection. The PE is x64 Native, has DriverEntry as entry point,
NX/dynamic-base/integrity-check flags, and imports only ntoskrnl.exe and
fwpkclnt.sys (Wdmsec is statically linked). It is unsigned. These checks do not
establish kernel runtime safety. No Driver Verifier, VM load, live cancellation,
IPv4/IPv6 traffic, concurrent unload, or interoperability tests were performed.

## Independent configuration ABI

Device: `\\.\ProxSepDrv`, restricted to SYSTEM/Administrators, exclusive logical
controller file. IOCTLs additionally check caller PID against the opening PID.

IOCTL **0x12E004** is METHOD_BUFFERED with read/write access, exact input 64 bytes:

| Offset | Length | Meaning |
| --- | --- | --- |
| 0 | 4 | ASCII PXRS |
| 4 | 4 | LE u32 ABI version 1 |
| 8 | 4 | LE u32 size 64 |
| 12 | 4 | LE u32 controller PID (must be opening/calling PID) |
| 16 | 4 | LE u32 flags: exactly 1, automatic TCP redirect |
| 20 | 16 | Windows SOCKADDR_IN: family 2 LE, port BE, 127.0.0.1, zero padding |
| 36 | 28 | Windows SOCKADDR_IN6: family 23 LE, port BE, zero flowinfo, ::1, scope 0 |

Port zero disables that address family; at least one port must be nonzero. All
other flags, addresses, nonzero padding, and ABI versions are rejected. Configure
only while stopped. Configure, then original-observed START 0x120004; STOP
0x120008. Owner cleanup/close stops and invalidates configuration. Query VERSION
0x12000C returns 120 (observed wire value, not a claim of implementation parity).

Automatic mode redirects only eligible TCP connects. The owner PID is exempt.
Existing WFP redirected connections are bypassed to avoid loops/overwriting
another redirector. A cached redirect handle and localRedirectTargetPID are set.
localRedirectContext is a **304-byte EventRecord header plus app-ID bytes**:
size@0=304, extra/app length@24/28, type@32=2, PID@36, protocol@180=6,
optional endpoint@192, original source sockaddr28@248, original destination
sockaddr28@276. Both sockaddrs are copied from the original CONNECT_REQUEST,
including IPv6 flowinfo and scope, not rebuilt from address-only filter values.
App-ID is the WFP application identity blob, normally UTF-16LE
device-path text. Unknown/SID/link fields are zero. The context is allocated
nonpaged NX and transferred to WFP by ApplyModifiedLayerData.

The user proxy must query redirect context and records on its accepted socket,
then set those records on the outbound socket **before connect**. This preserves
WFP logical-flow identity. The independent config must match the listeners the
controller actually opened. No authentication of a listener's socket ownership
is available through this ABI beyond its process PID.

## Pending compatibility subset

The observed 51256-byte CONFIGURE 0x120010 validates exact size, owner PID and
known reserved/count constraints, then uses **only the observed PID/capture
flags** to select pending mode. Other opaque config bytes are not interpreted;
this is not full config parity. TCP and eligible non-DNS UDP connects can pend.
POLL_EVENT 0x120014 is nonblocking: NO_MORE_ENTRIES when empty, bounded to 256
pending classifications / 2048 app-ID bytes each. Responses 0x12001C must be
exactly 304 bytes. Flag 2 changes destination and attaches the same full context;
zero flags permits unchanged. Retention flag 4 and all other flags are rejected.
Responses, expiry, stop and owner close atomically remove each pending owner
before exactly one complete/release. Expiry is strictly after 10 seconds and is
swept on callbacks/polls, not by timer. Three abandoned sweep batches stop
capture. Counter 0x120020 reports size12, flowcount0, pending-count: no flow
tracking is implemented.

All IRPs complete synchronously; none are queued or have cancellation callbacks.
User cancellation therefore cannot leave a pended IRP referencing its buffers.
Callouts and IOCTLs have unload rundown protection; a spinlock protects bounded
state. A generation-tagged gate owns callback snapshots, pending reservations,
detached responses and completion operations through their final Apply/Complete/
Release. STOP changes generation, enters Stopping, drains pending owners
unchanged, and at PASSIVE_LEVEL waits for in-flight ownership to reach zero.
Configure/START are refused during Stopping. An operation already committing a
modification can finish while STOP waits, but cannot outlive STOP completion or
carry old listener/PID/mode across a new START. Emergency stop is nonblocking
at callback IRQL and remains Stopping until final ownership drains. WFP DDIs are
not invoked under the global state spinlock. Owner cleanup marks the controller
closing before stopping, so concurrent IOCTLs cannot revive it. Previously
redirected established connections are not recalled.

## Explicit omissions and conservative behavior

- No DNS datagram inspection/block/parse/reinjection: IOCTL 0x120018 returns
  STATUS_NOT_IMPLEMENTED, and automatic mode bypasses UDP. Original UDP data
  handling was DNS port53 only; general UDP tunneling is not claimed.
- No stream reinjection: 0x120024 returns STATUS_NOT_IMPLEMENTED (matching the
  observed original handler), and no stream filters are registered.
- No auth-connect block/observe, flow establishment/deletion tracking, SID
  copying, retained redirect contexts/60s flow cleanup, logs or full counters.
- No automatic driver installation/service/INF/signing. No ARM64 or Win7 build.
  ExAllocatePool2 makes this implementation require Windows10 version2004+.
- App IDs larger than2048, full pending queue, unsupported/malformed metadata,
  writable-data/allocation failure bypass capture (fail open). Pending control
  errors return actual NTSTATUS instead of simulated success.
- No chained redirector support: redirected-by-other is conservatively bypassed.
- Only loopback listener destinations are supported by the independent ABI.
  Explicit non-loopback bound source addresses (including scoped IPv6) are
  conservatively bypassed; pending redirect responses return NOT_SUPPORTED.
  ANY/loopback binds remain eligible. Interface-local listener/zone selection
  remains unimplemented rather than forcing an invalid cross-zone redirect.
  Live scoped IPv6 connections and WFP unload/DDI failures still require VM
  validation. Barrier tests exercise the shared policy gate with mocked DDI
  completion/release accounting, not the Windows kernel scheduling/DDIs.

Primary implementation references:
[Microsoft windows-drivers-rs](https://github.com/microsoft/windows-drivers-rs),
[WFP connect redirection](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/using-bind-or-connect-redirection),
[Acquire writable data](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpsacquirewritablelayerdatapointer0),
[connect request](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/ns-fwpsk-fwps_connect_request0).
