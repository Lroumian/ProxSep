#![no_std]

pub const EVENT_SIZE: usize = 304;
pub const CONFIG_SIZE: usize = 51_256;
pub const MAX_APP_ID: usize = 2048;
pub const MAX_PENDING: usize = 256;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
enum Phase {
    #[default]
    Stopped = 0,
    Running,
    Stopping,
}

/// Spinlock-protected in the kernel. Tokens remain owned until the final WFP
/// Apply/Complete/Release, including responses detached from the pending table.
#[derive(Clone, Copy, Debug, Default)]
pub struct EpochGate {
    phase: Phase,
    generation: u64,
    in_flight: u32,
    drained: bool,
}
impl EpochGate {
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn is_running(&self) -> bool {
        self.phase == Phase::Running
    }
    pub fn is_stopped(&self) -> bool {
        self.phase == Phase::Stopped
    }
    pub fn can_configure(&self) -> bool {
        self.is_stopped() && self.in_flight == 0
    }
    pub fn start(&mut self) -> bool {
        if !self.can_configure() {
            return false;
        }
        self.generation = self.generation.wrapping_add(1);
        self.phase = Phase::Running;
        self.drained = false;
        true
    }
    pub fn may_modify(&self, generation: u64) -> bool {
        self.is_running() && self.generation == generation
    }
    pub fn enter(&mut self) -> Option<u64> {
        if !self.is_running() {
            None
        } else {
            self.enter_completion()
        }
    }
    pub fn enter_completion(&mut self) -> Option<u64> {
        self.in_flight = self.in_flight.checked_add(1)?;
        Some(self.generation)
    }
    pub fn begin_stop(&mut self) -> bool {
        if self.phase == Phase::Stopping {
            return false;
        }
        self.generation = self.generation.wrapping_add(1);
        self.phase = Phase::Stopping;
        self.drained = false;
        true
    }
    fn settle(&mut self) {
        if self.phase == Phase::Stopping && self.drained && self.in_flight == 0 {
            self.phase = Phase::Stopped;
        }
    }
    pub fn mark_drained(&mut self) {
        self.drained = true;
        self.settle();
    }
    pub fn leave(&mut self) -> bool {
        if self.in_flight == 0 {
            return false;
        }
        self.in_flight -= 1;
        self.settle();
        true
    }
}

pub fn copy_original_addresses(
    event: &mut [u8; 304],
    local: &[u8],
    remote: &[u8],
) -> Result<(), Error> {
    let family = local.get(..2).ok_or(Error::Length)?;
    let size = if family == 2u16.to_le_bytes() {
        16
    } else if family == 23u16.to_le_bytes() {
        28
    } else {
        return Err(Error::AddressFamily);
    };
    if remote.get(..2) != Some(family) {
        return Err(Error::AddressFamily);
    }
    if local.len() < size || remote.len() < size {
        return Err(Error::Length);
    }
    event[248..304].fill(0);
    event[248..248 + size].copy_from_slice(&local[..size]);
    event[276..276 + size].copy_from_slice(&remote[..size]);
    Ok(())
}

/// The current independent ABI has loopback listeners only. Explicit binds to
/// non-loopback sources need interface-local listeners and are bypassed.
pub fn loopback_redirect_source_allowed(source: &[u8]) -> bool {
    match source.get(..2) {
        Some(family) if family == 2u16.to_le_bytes() && source.len() >= 16 => {
            source[4..8] == [0; 4] || source[4] == 127
        }
        Some(family) if family == 23u16.to_le_bytes() && source.len() >= 28 => {
            source[8..24] == [0; 16]
                || (source[8..23] == [0; 15] && source[23] == 1 && source[24..28] == [0; 4])
        }
        _ => false,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Length,
    Size,
    Count,
    Reserved,
    Owner,
    AddressFamily,
    Flags,
}

pub fn read_u32(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}
pub fn read_u64(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes([
        bytes[at],
        bytes[at + 1],
        bytes[at + 2],
        bytes[at + 3],
        bytes[at + 4],
        bytes[at + 5],
        bytes[at + 6],
        bytes[at + 7],
    ])
}

pub fn validate_config(bytes: &[u8], owner_pid: u32) -> Result<(), Error> {
    if bytes.len() != CONFIG_SIZE {
        return Err(Error::Length);
    }
    if read_u32(bytes, 0) != CONFIG_SIZE as u32 {
        return Err(Error::Size);
    }
    if read_u32(bytes, 4) != owner_pid || owner_pid == 0 {
        return Err(Error::Owner);
    }
    if read_u32(bytes, 51_052) > 1000 {
        return Err(Error::Count);
    }
    if bytes[50_047] != 0 || bytes[50_048] != 0 {
        return Err(Error::Reserved);
    }
    Ok(())
}

pub fn validate_response(bytes: &[u8], original_family: u16) -> Result<(), Error> {
    if bytes.len() != EVENT_SIZE {
        return Err(Error::Length);
    }
    if read_u32(bytes, 0) != EVENT_SIZE as u32 {
        return Err(Error::Size);
    }
    let flags = read_u32(bytes, 204);
    if flags & !2 != 0 {
        return Err(Error::Flags);
    }
    if flags & 2 != 0 {
        let family = u16::from_le_bytes([bytes[276], bytes[277]]);
        if family != original_family || (family != 2 && family != 23) {
            return Err(Error::AddressFamily);
        }
    }
    Ok(())
}

pub fn should_capture(
    active: bool,
    process_pid: u32,
    proxy_pid: u32,
    protocol: u8,
    remote_port: u16,
) -> bool {
    active && process_pid != proxy_pid && (protocol == 6 || protocol == 17 && remote_port != 53)
}

pub fn expired(now_ticks: u64, created_ticks: u64) -> bool {
    now_ticks > created_ticks.saturating_add(100_000_000)
}

pub fn validate_independent_config(bytes: &[u8], owner_pid: u32) -> Result<(), Error> {
    if bytes.len() != 64 {
        return Err(Error::Length);
    }
    if &bytes[..4] != b"PXRS" || read_u32(bytes, 4) != 1 || read_u32(bytes, 8) != 64 {
        return Err(Error::Size);
    }
    if owner_pid == 0 || read_u32(bytes, 12) != owner_pid {
        return Err(Error::Owner);
    }
    if read_u32(bytes, 16) != 1 {
        return Err(Error::Flags);
    }
    if bytes[20..22] != 2u16.to_le_bytes() || bytes[36..38] != 23u16.to_le_bytes() {
        return Err(Error::AddressFamily);
    }
    if bytes[24..28] != [127, 0, 0, 1]
        || bytes[28..36].iter().any(|&b| b != 0)
        || bytes[40..59].iter().any(|&b| b != 0)
        || bytes[59] != 1
        || bytes[60..64].iter().any(|&b| b != 0)
    {
        return Err(Error::Reserved);
    }
    if bytes[22..24] == [0, 0] && bytes[38..40] == [0, 0] {
        return Err(Error::Flags);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stop_invalidates_old_callback_and_waits_for_detached_response() {
        let mut gate = EpochGate::default();
        assert!(gate.start());
        let callback = gate.enter().unwrap();
        let response = gate.enter().unwrap();
        assert!(gate.begin_stop());
        gate.mark_drained();
        assert!(!gate.may_modify(callback));
        assert!(!gate.can_configure());
        assert!(!gate.start());
        assert!(gate.leave());
        assert!(!gate.is_stopped());
        assert!(gate.leave());
        assert!(gate.is_stopped());
        assert!(gate.can_configure());
        assert!(gate.start());
        assert!(!gate.may_modify(response));
        let current = gate.enter().unwrap();
        assert!(gate.may_modify(current));
        assert!(gate.leave());
    }
    #[test]
    fn stop_cannot_finish_until_pending_completions_and_drain_are_done() {
        let mut gate = EpochGate::default();
        assert!(gate.start());
        gate.begin_stop();
        let _completion = gate.enter_completion().unwrap();
        assert!(!gate.begin_stop());
        assert!(gate.leave());
        assert!(!gate.is_stopped());
        gate.mark_drained();
        assert!(gate.is_stopped());
        assert!(!gate.leave());
    }
    #[test]
    fn complete_ipv6_sockaddr_survives_context_and_bound_source_policy() {
        let mut event = [0u8; 304];
        let mut local = [0u8; 28];
        let mut remote = [0u8; 28];
        local[..2].copy_from_slice(&23u16.to_le_bytes());
        remote[..2].copy_from_slice(&23u16.to_le_bytes());
        remote[4..8].copy_from_slice(&0x12345678u32.to_le_bytes());
        remote[8..24].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        remote[24..28].copy_from_slice(&7u32.to_le_bytes());
        copy_original_addresses(&mut event, &local, &remote).unwrap();
        assert_eq!(&event[276..304], &remote);
        assert!(loopback_redirect_source_allowed(&local));
        local[23] = 1;
        assert!(loopback_redirect_source_allowed(&local));
        local[8] = 0xfe;
        local[9] = 0x80;
        local[24] = 7;
        assert!(!loopback_redirect_source_allowed(&local));
        let mut v4 = [0u8; 16];
        v4[..2].copy_from_slice(&2u16.to_le_bytes());
        assert!(loopback_redirect_source_allowed(&v4));
        v4[4..8].copy_from_slice(&[127, 0, 0, 1]);
        assert!(loopback_redirect_source_allowed(&v4));
        v4[4..8].copy_from_slice(&[192, 168, 1, 4]);
        assert!(!loopback_redirect_source_allowed(&v4));
    }
    #[test]
    fn independent_config_requires_loopback_and_owner() {
        let mut config = [0u8; 64];
        config[..4].copy_from_slice(b"PXRS");
        config[4..8].copy_from_slice(&1u32.to_le_bytes());
        config[8..12].copy_from_slice(&64u32.to_le_bytes());
        config[12..16].copy_from_slice(&7u32.to_le_bytes());
        config[16..20].copy_from_slice(&1u32.to_le_bytes());
        config[20..22].copy_from_slice(&2u16.to_le_bytes());
        config[22..24].copy_from_slice(&1080u16.to_be_bytes());
        config[24..28].copy_from_slice(&[127, 0, 0, 1]);
        config[36..38].copy_from_slice(&23u16.to_le_bytes());
        config[59] = 1;
        assert!(validate_independent_config(&config, 7).is_ok());
        assert!(validate_independent_config(&config, 8).is_err());
        config[24] = 192;
        assert!(validate_independent_config(&config, 7).is_err());
    }
    #[test]
    fn own_proxy_and_dns_udp_do_not_redirect() {
        assert!(!should_capture(true, 7, 7, 6, 443));
        assert!(!should_capture(true, 8, 7, 17, 53));
        assert!(should_capture(true, 8, 7, 6, 443));
        assert!(!should_capture(false, 8, 7, 6, 443));
    }
    #[test]
    fn configuration_rejects_pid_impersonation_and_bad_reserved_bytes() {
        let mut config = [0; 51_256];
        config[..4].copy_from_slice(&51_256u32.to_le_bytes());
        config[4..8].copy_from_slice(&7u32.to_le_bytes());
        assert!(validate_config(&config, 7).is_ok());
        assert!(validate_config(&config, 8).is_err());
        config[50_048] = 1;
        assert!(validate_config(&config, 7).is_err());
    }
    #[test]
    fn response_requires_header_and_matching_family() {
        let mut response = [0; 304];
        response[..4].copy_from_slice(&304u32.to_le_bytes());
        response[204..208].copy_from_slice(&2u32.to_le_bytes());
        response[276..278].copy_from_slice(&2u16.to_le_bytes());
        assert!(validate_response(&response, 2).is_ok());
        assert!(validate_response(&response, 23).is_err());
        assert!(validate_response(&response[..303], 2).is_err());
    }
    #[test]
    fn pending_timeout_is_strict_and_overflow_does_not_expire() {
        assert!(!expired(100_000_005, 5));
        assert!(expired(100_000_006, 5));
        assert!(!expired(u64::MAX, u64::MAX - 9));
    }
}
