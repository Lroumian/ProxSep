//! Driver protocol recovered from static evidence; no automatic device access.

use std::collections::BTreeMap;
use std::fmt;

pub const IOCTL_START: u32 = 0x120004;
pub const IOCTL_STOP: u32 = 0x120008;
pub const IOCTL_VERSION: u32 = 0x12000C;
pub const IOCTL_CONFIGURE: u32 = 0x120010;
/// Separate ABI for our independent driver; never send to the original device.
pub const IOCTL_CONFIGURE_INDEPENDENT: u32 = 0x12E004;
pub const INDEPENDENT_DEVICE_PATH: &str = r"\\.\ProxSepDrv";
pub const IOCTL_POLL_EVENT: u32 = 0x120014;
pub const IOCTL_INJECT_DATAGRAM: u32 = 0x120018;
pub const IOCTL_CLASSIFY_RESPONSE: u32 = 0x12001C;
pub const IOCTL_COUNTERS: u32 = 0x120020;
/// The examined original returns STATUS_NOT_IMPLEMENTED for valid requests.
pub const IOCTL_INJECT_STREAM: u32 = 0x120024;
pub const DRIVER_VERSION: u32 = 120;
pub const EVENT_HEADER_SIZE: usize = 304;
pub const CONFIG_SIZE: usize = 51_256;
pub const DATAGRAM_HEADER_SIZE: usize = 56;
pub const MAX_EVENT_EXTRA_BYTES: usize = 1_000_000;
pub const PENDING_TIMEOUT_TICKS: u64 = 100_000_000;
pub const RETAINED_TIMEOUT_TICKS: u64 = 600_000_000;
pub const RESPONSE_REDIRECT: u32 = 2;
pub const RESPONSE_RETAIN: u32 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    Length { expected: usize, actual: usize },
    InvalidField(&'static str),
}

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Length { expected, actual } => {
                write!(f, "expected {expected} bytes, received {actual}")
            }
            Self::InvalidField(name) => write!(f, "invalid driver field: {name}"),
        }
    }
}

impl std::error::Error for CodecError {}

fn exact(bytes: &[u8], expected: usize) -> Result<(), CodecError> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(CodecError::Length {
            expected,
            actual: bytes.len(),
        })
    }
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    let mut value = [0; 4];
    value.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(value)
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    let mut value = [0; 8];
    value.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(value)
}

/// Versioned 64-byte configuration for the independently written driver only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndependentConfig([u8; 64]);

impl IndependentConfig {
    /// Automatic TCP redirection to IPv4/IPv6 loopback listeners. A zero port
    /// disables that family. The kernel verifies PID against the opening caller.
    pub fn new(owner_pid: u32, ipv4_port: u16, ipv6_port: u16) -> Result<Self, CodecError> {
        if owner_pid == 0 {
            return Err(CodecError::InvalidField("independent owner PID"));
        }
        if ipv4_port == 0 && ipv6_port == 0 {
            return Err(CodecError::InvalidField("no independent listener"));
        }
        let mut bytes = [0u8; 64];
        bytes[..4].copy_from_slice(b"PXRS");
        bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&64u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&owner_pid.to_le_bytes());
        bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
        bytes[20..22].copy_from_slice(&2u16.to_le_bytes());
        bytes[22..24].copy_from_slice(&ipv4_port.to_be_bytes());
        bytes[24..28].copy_from_slice(&[127, 0, 0, 1]);
        bytes[36..38].copy_from_slice(&23u16.to_le_bytes());
        bytes[38..40].copy_from_slice(&ipv6_port.to_be_bytes());
        bytes[59] = 1;
        Ok(Self(bytes))
    }
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

/// Opaque original configuration. Unknown fields are not synthesized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverConfig(Box<[u8]>);

impl DriverConfig {
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        exact(bytes, CONFIG_SIZE)?;
        if u32_at(bytes, 0) != CONFIG_SIZE as u32 {
            return Err(CodecError::InvalidField("config size"));
        }
        if u32_at(bytes, 51_052) > 1000 {
            return Err(CodecError::InvalidField("config count at51052"));
        }
        if bytes[50_047] != 0 || bytes[50_048] != 0 {
            return Err(CodecError::InvalidField("reserved config bytes"));
        }
        Ok(Self(bytes.into()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn process_id(&self) -> u32 {
        u32_at(&self.0, 4)
    }
    pub fn capture_flags(&self) -> u32 {
        u32_at(&self.0, 8)
    }
    pub fn event_timeout_seconds(&self) -> u32 {
        u32_at(&self.0, 20)
    }
    pub fn retain_completed_contexts(&self) -> bool {
        u32_at(&self.0, 51_052) != 0 || self.0[51_056] != 0
    }
}

/// Fixed header preserves opaque fields, including the original union values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventRecord {
    header: [u8; EVENT_HEADER_SIZE],
    extra: Vec<u8>,
}

impl EventRecord {
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() < EVENT_HEADER_SIZE {
            return Err(CodecError::Length {
                expected: EVENT_HEADER_SIZE,
                actual: bytes.len(),
            });
        }
        if u32_at(bytes, 0) != EVENT_HEADER_SIZE as u32 {
            return Err(CodecError::InvalidField("event header size"));
        }
        let extra_size = u32_at(bytes, 24) as usize;
        if extra_size > MAX_EVENT_EXTRA_BYTES {
            return Err(CodecError::InvalidField("event extra length"));
        }
        exact(bytes, EVENT_HEADER_SIZE + extra_size)?;
        if u32_at(bytes, 28) as usize > extra_size {
            return Err(CodecError::InvalidField("application-id length"));
        }
        let mut header = [0; EVENT_HEADER_SIZE];
        header.copy_from_slice(&bytes[..EVENT_HEADER_SIZE]);
        Ok(Self {
            header,
            extra: bytes[EVENT_HEADER_SIZE..].to_vec(),
        })
    }

    /// Build a fresh record with zeroed opaque fields, useful for independent
    /// driver implementations and deterministic fixtures.
    pub fn new(event_type: u32, application_id: &[u8], payload: &[u8]) -> Result<Self, CodecError> {
        let extra_size = application_id
            .len()
            .checked_add(payload.len())
            .ok_or(CodecError::InvalidField("event extra length"))?;
        if extra_size > MAX_EVENT_EXTRA_BYTES {
            return Err(CodecError::InvalidField("event extra length"));
        }
        let mut header = [0; EVENT_HEADER_SIZE];
        header[..4].copy_from_slice(&(EVENT_HEADER_SIZE as u32).to_le_bytes());
        header[24..28].copy_from_slice(&(extra_size as u32).to_le_bytes());
        header[28..32].copy_from_slice(&(application_id.len() as u32).to_le_bytes());
        header[32..36].copy_from_slice(&event_type.to_le_bytes());
        let mut extra = Vec::with_capacity(extra_size);
        extra.extend_from_slice(application_id);
        extra.extend_from_slice(payload);
        Ok(Self { header, extra })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut wire = Vec::with_capacity(EVENT_HEADER_SIZE + self.extra.len());
        wire.extend_from_slice(&self.header);
        wire.extend_from_slice(&self.extra);
        wire
    }

    pub fn header(&self) -> &[u8; EVENT_HEADER_SIZE] {
        &self.header
    }
    pub fn application_id(&self) -> &[u8] {
        &self.extra[..u32_at(&self.header, 28) as usize]
    }
    pub fn payload(&self) -> &[u8] {
        &self.extra[u32_at(&self.header, 28) as usize..]
    }
    pub fn event_type(&self) -> u32 {
        u32_at(&self.header, 32)
    }
    pub fn process_id(&self) -> u32 {
        u32_at(&self.header, 36)
    }
    pub fn flow_handle(&self) -> u64 {
        u64_at(&self.header, 168)
    }
    pub fn inbound(&self) -> bool {
        self.header[176] != 0
    }
    pub fn protocol(&self) -> u32 {
        u32_at(&self.header, 180)
    }
    pub fn classify_handle(&self) -> u64 {
        u64_at(&self.header, 184)
    }
    pub fn endpoint_handle(&self) -> u64 {
        u64_at(&self.header, 192)
    }
    pub fn response_flags(&self) -> u32 {
        u32_at(&self.header, 204)
    }
    pub fn timestamp_ticks(&self) -> u64 {
        u64_at(&self.header, 208)
    }
    pub fn source_sockaddr(&self) -> &[u8] {
        &self.header[248..276]
    }
    pub fn destination_sockaddr(&self) -> &[u8] {
        &self.header[276..304]
    }

    /// Responses must be exactly304 bytes, irrespective of original payload.
    /// The optional destination must be the complete28-byte sockaddr slot.
    pub fn classify_response(
        &self,
        flags: u32,
        destination: Option<&[u8]>,
    ) -> Result<[u8; EVENT_HEADER_SIZE], CodecError> {
        let mut response = self.header;
        response[204..208].copy_from_slice(&flags.to_le_bytes());
        if let Some(address) = destination {
            exact(address, 28)?;
            response[276..304].copy_from_slice(address);
        }
        Ok(response)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DatagramInjection {
    header: [u8; DATAGRAM_HEADER_SIZE],
    packet: Vec<u8>,
}

impl DatagramInjection {
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() < DATAGRAM_HEADER_SIZE {
            return Err(CodecError::Length {
                expected: DATAGRAM_HEADER_SIZE,
                actual: bytes.len(),
            });
        }
        if u32_at(bytes, 0) != DATAGRAM_HEADER_SIZE as u32 {
            return Err(CodecError::InvalidField("datagram header size"));
        }
        let packet_size = u32_at(bytes, 4) as usize;
        let expected = DATAGRAM_HEADER_SIZE
            .checked_add(packet_size)
            .ok_or(CodecError::InvalidField("datagram length"))?;
        exact(bytes, expected)?;
        let mut header = [0; DATAGRAM_HEADER_SIZE];
        header.copy_from_slice(&bytes[..DATAGRAM_HEADER_SIZE]);
        Ok(Self {
            header,
            packet: bytes[DATAGRAM_HEADER_SIZE..].to_vec(),
        })
    }

    /// Build from a DNS event using the observed packet/metadata offsets.
    pub fn from_dns_event(event: &EventRecord) -> Result<Self, CodecError> {
        if event.event_type() != 3 || event.protocol() != 17 {
            return Err(CodecError::InvalidField("DNS datagram event"));
        }
        let mut header = [0; DATAGRAM_HEADER_SIZE];
        header[..4].copy_from_slice(&(DATAGRAM_HEADER_SIZE as u32).to_le_bytes());
        header[4..8].copy_from_slice(&(event.payload().len() as u32).to_le_bytes());
        header[8..10].copy_from_slice(&event.header[276..278]);
        header[16..28].copy_from_slice(&event.header[216..228]);
        header[40..48].copy_from_slice(&event.header[240..248]);
        header[48] = u8::from(event.inbound());
        Ok(Self {
            header,
            packet: event.payload().to_vec(),
        })
    }

    pub fn header(&self) -> &[u8; DATAGRAM_HEADER_SIZE] {
        &self.header
    }
    pub fn packet(&self) -> &[u8] {
        &self.packet
    }
    pub fn inbound(&self) -> bool {
        self.header[48] != 0
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut wire = Vec::with_capacity(DATAGRAM_HEADER_SIZE + self.packet.len());
        wire.extend_from_slice(&self.header);
        wire.extend_from_slice(&self.packet);
        wire
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverCounters {
    pub flow_count: u32,
    pub redirect_count: u32,
}

impl DriverCounters {
    pub fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        exact(bytes, 12)?;
        if u32_at(bytes, 0) != 12 {
            return Err(CodecError::InvalidField("counter header size"));
        }
        Ok(Self {
            flow_count: u32_at(bytes, 4),
            redirect_count: u32_at(bytes, 8),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleError {
    MissingConfiguration,
    AlreadyActive,
    Inactive,
    DuplicateHandle,
    UnknownHandle,
}

#[derive(Debug, Clone, Copy)]
struct PendingContext {
    created_ticks: u64,
    completed: bool,
}

/// A pure user-mode model of recovered lifecycle. It performs no WFP actions.
#[derive(Debug, Default)]
pub struct EngineModel {
    configured: bool,
    active: bool,
    abandoned_batches: u32,
    contexts: BTreeMap<u64, PendingContext>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct SweepResult {
    pub abandoned_handles: Vec<u64>,
    pub released_retained_handles: Vec<u64>,
    pub stopped_pending_handles: Vec<u64>,
    pub emergency_stop: bool,
}

impl EngineModel {
    pub fn configure(&mut self) {
        self.configured = true;
    }
    pub fn is_active(&self) -> bool {
        self.active
    }
    pub fn abandoned_batches(&self) -> u32 {
        self.abandoned_batches
    }
    pub fn context_count(&self) -> usize {
        self.contexts.len()
    }
    pub fn start(&mut self) -> Result<(), LifecycleError> {
        if !self.configured {
            return Err(LifecycleError::MissingConfiguration);
        }
        if self.active {
            return Err(LifecycleError::AlreadyActive);
        }
        self.active = true;
        Ok(())
    }
    pub fn pend(&mut self, handle: u64, created_ticks: u64) -> Result<(), LifecycleError> {
        if !self.active {
            return Err(LifecycleError::Inactive);
        }
        if self.contexts.contains_key(&handle) {
            return Err(LifecycleError::DuplicateHandle);
        }
        self.contexts.insert(
            handle,
            PendingContext {
                created_ticks,
                completed: false,
            },
        );
        Ok(())
    }
    pub fn complete(&mut self, handle: u64, retain: bool) -> Result<(), LifecycleError> {
        if !self.active {
            return Err(LifecycleError::Inactive);
        }
        let context = self
            .contexts
            .get_mut(&handle)
            .ok_or(LifecycleError::UnknownHandle)?;
        // A retained context's WFP classify handle was already released.
        if context.completed {
            return Err(LifecycleError::UnknownHandle);
        }
        self.abandoned_batches = 0;
        if retain {
            context.completed = true;
        } else {
            self.contexts.remove(&handle);
        }
        Ok(())
    }
    pub fn stop(&mut self) -> Result<Vec<u64>, LifecycleError> {
        if !self.active {
            return Err(LifecycleError::Inactive);
        }
        self.active = false;
        let pending = self
            .contexts
            .iter()
            .filter(|(_, context)| !context.completed)
            .map(|(&handle, _)| handle)
            .collect();
        self.contexts.clear();
        Ok(pending)
    }
    pub fn sweep(&mut self, now_ticks: u64) -> SweepResult {
        let mut result = SweepResult::default();
        self.contexts.retain(|&handle, context| {
            let timeout = if context.completed {
                RETAINED_TIMEOUT_TICKS
            } else {
                PENDING_TIMEOUT_TICKS
            };
            if now_ticks > context.created_ticks.saturating_add(timeout) {
                if context.completed {
                    result.released_retained_handles.push(handle);
                } else {
                    result.abandoned_handles.push(handle);
                }
                false
            } else {
                true
            }
        });
        if !result.abandoned_handles.is_empty() {
            self.abandoned_batches += 1;
            if self.abandoned_batches > 2 {
                self.abandoned_batches = 0;
                result.emergency_stop = true;
                result.stopped_pending_handles = self.stop().unwrap_or_default();
            }
        }
        result
    }
}

pub mod device;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn independent_device_uses_proxsep_namespace() {
        assert_eq!(INDEPENDENT_DEVICE_PATH, r"\\.\ProxSepDrv");
    }
    #[test]
    fn independent_config_is_separate_exact64_loopback_abi() {
        let config = IndependentConfig::new(7, 1080, 0).unwrap();
        let bytes = config.as_bytes();
        assert_eq!(&bytes[..4], b"PXRS");
        assert_eq!(u32_at(bytes, 4), 1);
        assert_eq!(u32_at(bytes, 8), 64);
        assert_eq!(u32_at(bytes, 12), 7);
        assert_eq!(&bytes[22..24], &1080u16.to_be_bytes());
        assert_eq!(&bytes[24..28], &[127, 0, 0, 1]);
        assert_eq!(bytes[59], 1);
        assert!(IndependentConfig::new(7, 0, 0).is_err());
        assert!(IndependentConfig::new(0, 1080, 0).is_err());
    }

    #[test]
    fn explicitly_named_device_rejects_filesystem_and_pipe_paths_without_opening() {
        for path in [
            "C:\\data.bin",
            r"\\.\pipe\something",
            r"\\.\",
            r"\\.\name/other",
        ] {
            assert_eq!(
                device::DriverDevice::open_path(path).unwrap_err().kind(),
                std::io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn event_decoder_checks_lengths_and_preserves_unknown_header() {
        let mut wire = vec![0u8; 307];
        wire[0..4].copy_from_slice(&304u32.to_le_bytes());
        wire[24..28].copy_from_slice(&3u32.to_le_bytes());
        wire[28..32].copy_from_slice(&1u32.to_le_bytes());
        wire[32..36].copy_from_slice(&2u32.to_le_bytes());
        wire[4] = 0xA7;
        wire[304..].copy_from_slice(&[1, 2, 3]);
        let event = EventRecord::decode(&wire).unwrap();
        assert_eq!(event.application_id(), &[1]);
        assert_eq!(event.payload(), &[2, 3]);
        assert_eq!(event.encode(), wire);
        assert!(EventRecord::decode(&wire[..306]).is_err());
        wire[28..32].copy_from_slice(&4u32.to_le_bytes());
        assert!(EventRecord::decode(&wire).is_err());
    }

    #[test]
    fn observed_config_reserved_constraints_are_enforced() {
        let mut config = vec![0u8; 51_256];
        config[..4].copy_from_slice(&51_256u32.to_le_bytes());
        config[51_052..51_056].copy_from_slice(&1000u32.to_le_bytes());
        assert!(DriverConfig::decode(&config).is_ok());
        config[50_047] = 1;
        assert!(DriverConfig::decode(&config).is_err());
    }

    #[test]
    fn abandonment_is_counted_per_batch_and_completion_resets_it() {
        let mut engine = EngineModel::default();
        engine.configure();
        engine.start().unwrap();
        for batch in 0..2 {
            for i in 0..3 {
                engine.pend(batch * 10 + i, batch * 200_000_000).unwrap();
            }
            let expired = engine.sweep(batch * 200_000_000 + 100_000_001);
            assert_eq!(expired.abandoned_handles.len(), 3);
            assert!(!expired.emergency_stop);
        }
        engine.pend(99, 500_000_000).unwrap();
        engine.complete(99, false).unwrap();
        assert_eq!(engine.abandoned_batches(), 0);
        for batch in 0..3 {
            engine
                .pend(100 + batch, 600_000_000 + batch * 200_000_000)
                .unwrap();
            let expired = engine.sweep(700_000_001 + batch * 200_000_000);
            assert_eq!(expired.emergency_stop, batch == 2);
        }
        assert!(!engine.is_active());
    }

    #[test]
    fn timeout_boundary_and_retained_age_use_original_creation() {
        let mut engine = EngineModel::default();
        engine.configure();
        engine.start().unwrap();
        engine.pend(1, 7).unwrap();
        assert!(engine.sweep(100_000_007).abandoned_handles.is_empty());
        engine.complete(1, true).unwrap();
        assert!(
            engine
                .sweep(600_000_007)
                .released_retained_handles
                .is_empty()
        );
        assert_eq!(engine.sweep(600_000_008).released_retained_handles, vec![1]);
    }

    #[test]
    fn response_discards_payload_but_keeps_handle_and_sockaddr() {
        let mut wire = EventRecord::new(2, &[1, 2], &[3]).unwrap().encode();
        wire[184..192].copy_from_slice(&42u64.to_le_bytes());
        let event = EventRecord::decode(&wire).unwrap();
        let mut sockaddr = [0; 28];
        sockaddr[..2].copy_from_slice(&2u16.to_le_bytes());
        sockaddr[2..4].copy_from_slice(&1080u16.to_be_bytes());
        let response = event
            .classify_response(RESPONSE_REDIRECT, Some(&sockaddr))
            .unwrap();
        assert_eq!(response.len(), 304);
        assert_eq!(u64_at(&response, 184), 42);
        assert_eq!(u32_at(&response, 204), 2);
        assert_eq!(&response[276..304], &sockaddr);
        assert!(event.classify_response(2, Some(&sockaddr[..27])).is_err());
    }

    #[test]
    fn datagram_codec_roundtrips_opaque_fields_and_rejects_truncation() {
        let mut wire = vec![0; 59];
        wire[..4].copy_from_slice(&56u32.to_le_bytes());
        wire[4..8].copy_from_slice(&3u32.to_le_bytes());
        wire[8..10].copy_from_slice(&23u16.to_le_bytes());
        wire[40..48].copy_from_slice(&77u64.to_le_bytes());
        wire[48] = 1;
        wire[55] = 0xA3;
        wire[56..].copy_from_slice(&[5, 6, 7]);
        let packet = DatagramInjection::decode(&wire).unwrap();
        assert!(packet.inbound());
        assert_eq!(packet.packet(), &[5, 6, 7]);
        assert_eq!(packet.encode(), wire);
        assert!(DatagramInjection::decode(&wire[..58]).is_err());
        for length in 0..56 {
            assert!(DatagramInjection::decode(&wire[..length]).is_err());
        }
    }

    #[test]
    fn oversized_events_and_trailing_data_are_rejected() {
        let mut wire = vec![0; EVENT_HEADER_SIZE];
        wire[..4].copy_from_slice(&304u32.to_le_bytes());
        wire[24..28].copy_from_slice(&1_000_001u32.to_le_bytes());
        assert!(EventRecord::decode(&wire).is_err());
        wire[24..28].copy_from_slice(&0u32.to_le_bytes());
        for length in 0..304 {
            assert!(EventRecord::decode(&wire[..length]).is_err());
        }
        wire.push(0);
        assert!(EventRecord::decode(&wire).is_err());
    }

    #[test]
    fn model_preserves_pending_entry_on_duplicate_and_stop_reports_completion() {
        let mut engine = EngineModel::default();
        assert_eq!(engine.start(), Err(LifecycleError::MissingConfiguration));
        engine.configure();
        engine.start().unwrap();
        engine.pend(1, 0).unwrap();
        assert_eq!(engine.pend(1, 9), Err(LifecycleError::DuplicateHandle));
        engine.pend(2, 0).unwrap();
        engine.complete(2, true).unwrap();
        assert_eq!(engine.complete(2, true), Err(LifecycleError::UnknownHandle));
        assert_eq!(engine.stop().unwrap(), vec![1]);
        assert_eq!(engine.context_count(), 0);
        assert_eq!(engine.pend(3, 0), Err(LifecycleError::Inactive));
    }
}
