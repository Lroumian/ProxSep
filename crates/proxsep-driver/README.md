# Driver interface

Independent Rust codecs for the observed ProxifierDrv120 interface, with no
third-party dependencies. Analysis reports are intentionally excluded from the
repository.

- `DriverConfig` validates exactly51,256 bytes and preserves unknown fields.
- `EventRecord` validates304-byte header plus bounded variable data, app-id split,
  opaque fields and response framing.
- `DatagramInjection` handles56-byte transport-injection frames.
- `DriverCounters` decodes12-byte counter responses.
- `EngineModel` models strict10-second/60-second expiry and emergency stop after
  three abandoned sweep batches; successful completion resets the count.
- `device::DriverDevice` opens `\\.\ProxifierDrv` only when the caller explicitly
  invokes `open()`. No service loading, driver installation, or OS configuration
  occurs automatically. Calls use private overlapped events and cancel/drain on
  timeout before releasing Rust-owned buffers. Draining cancellation can extend
  beyond the requested timeout if a kernel driver does not promptly complete it.

Tests are entirely in-memory and never access an installed driver. The pure
lifecycle model rejects re-completion of an already completed classify handle;
this is a memory-safe implementation policy, not a claim about original invalid
request behavior. The stream IOCTL is documented as not implemented by the
examined driver; DNS-only packet interception is preserved in the evidence.

This crate is a user-mode codec/client and lifecycle model. A newly implemented
WFP kernel driver is now in `../../drivers/proxsep-wfp`; live interoperability
testing remains separate work.

## Independent device configuration

`DriverDevice::open()` remains the explicit original-device API. New callers for
the independent driver must use `open_path(INDEPENDENT_DEVICE_PATH)`; no device
is opened automatically. Names outside the flat DOS device namespace are
rejected. `IndependentConfig::new(owner_pid, ipv4_port, ipv6_port)` builds the
separate 64-byte PXRS/version1 config, loopback listeners only; a zero port
disables that family. `configure_independent` sends IOCTL0x12E004. This config is
not compatible with the original opaque 51256-byte config. See the independent
driver README for runtime-validation gaps. Unit tests never open any device.
