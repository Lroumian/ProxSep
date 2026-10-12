//! DNS policy and bounded placeholder addresses.
//!
//! Proxifier's public documentation describes automatic fallback, list inversion,
//! wildcard/macro exclusions, and 127.8.*.* placeholders:
//! <https://www.proxifier.com/docs/win-v4/dns.html>.
//! Allocation order, unknown auto-detection state, TTL, non-A forwarding and
//! NODATA responses below are reconstruction choices, not observed binary behavior.
//! Wire validation follows RFC 1035 and RFC 6891; no DNS network probe runs here.
use crate::profile::ResolveOptions;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DnsError {
    #[error("malformed DNS query: {0}")]
    MalformedQuery(&'static str),
    #[error("unsupported DNS class {0}")]
    UnsupportedClass(u16),
    #[error("unsupported DNS additional record type {0}")]
    UnsupportedAdditional(u16),
    #[error("unsupported DNS name encoding")]
    UnsupportedName,
    #[error("invalid hostname")]
    InvalidHost,
    #[error("fake IP map capacity must be between 1 and 65024")]
    InvalidCapacity,
    #[error("fake IP map exhausted; existing addresses cannot be reassigned")]
    Exhausted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsMode {
    Local,
    Remote,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalDnsState {
    Unknown,
    Available,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsModeChange {
    pub old: DnsMode,
    pub new: DnsMode,
}

#[derive(Debug, Clone)]
pub struct DnsPolicy {
    pub options: ResolveOptions,
    computer_name: String,
    pub local_dns_state: LocalDnsState,
}

impl DnsPolicy {
    pub fn new(options: ResolveOptions, computer_name: impl Into<String>) -> Self {
        Self {
            options,
            computer_name: computer_name
                .into()
                .trim_end_matches('.')
                .to_ascii_lowercase(),
            local_dns_state: LocalDnsState::Unknown,
        }
    }

    /// The caller supplies probe results. Until the first result, the stored
    /// profile's `via_proxy` is the fallback (an explicit reconstruction choice).
    pub fn effective_mode(&self) -> DnsMode {
        let remote = if self.options.auto_mode_detection {
            match self.local_dns_state {
                LocalDnsState::Available => false,
                LocalDnsState::Unavailable => true,
                LocalDnsState::Unknown => self.options.via_proxy,
            }
        } else {
            self.options.via_proxy
        };
        if remote {
            DnsMode::Remote
        } else {
            DnsMode::Local
        }
    }

    pub fn observe_local_dns(&mut self, available: bool) -> Option<DnsModeChange> {
        let old = self.effective_mode();
        self.local_dns_state = if available {
            LocalDnsState::Available
        } else {
            LocalDnsState::Unavailable
        };
        let new = self.effective_mode();
        (old != new).then_some(DnsModeChange { old, new })
    }

    pub fn mode_for_host(&self, host: &str) -> Result<DnsMode, DnsError> {
        if host.parse::<IpAddr>().is_ok() {
            return Ok(DnsMode::Local);
        }
        let host = canonical_host(host)?;
        if self.effective_mode() == DnsMode::Local {
            return Ok(DnsMode::Local);
        }
        let listed = self
            .options
            .exclusion_list
            .split([';', '\r', '\n'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .any(|pattern| {
                if pattern.eq_ignore_ascii_case("%SimpleHostnames%") {
                    !host.contains('.')
                } else {
                    // Replace each original occurrence once. Replacement text
                    // must not be reinterpreted as another macro.
                    let pattern = pattern
                        .to_ascii_lowercase()
                        .replace("%computername%", &self.computer_name);
                    wildcard_match(&pattern, &host)
                }
            });
        let remote = if self.options.exclusion_only_from_list {
            listed
        } else {
            !listed
        };
        Ok(if remote {
            DnsMode::Remote
        } else {
            DnsMode::Local
        })
    }
}

fn canonical_host(host: &str) -> Result<String, DnsError> {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty()
        || host.len() > 253
        || !host.is_ascii()
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        })
    {
        return Err(DnsError::InvalidHost);
    }
    Ok(host.to_ascii_lowercase())
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    let (pattern, text) = (pattern.as_bytes(), text.as_bytes());
    let (mut p, mut t, mut star, mut resume) = (0, 0, None, 0);
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            resume = t;
        } else if let Some(index) = star {
            resume += 1;
            t = resume;
            p = index + 1;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

pub const MAX_FAKE_IPS: usize = 256 * 254;

#[derive(Debug)]
pub struct FakeIpMap {
    capacity: usize,
    forward: HashMap<String, Ipv4Addr>,
    reverse: HashMap<Ipv4Addr, String>,
}

impl FakeIpMap {
    /// Never reuses an address. This protects live connections and application
    /// DNS caches; callers must retire the entire network session before reset.
    pub fn new(capacity: usize) -> Result<Self, DnsError> {
        if capacity == 0 || capacity > MAX_FAKE_IPS {
            return Err(DnsError::InvalidCapacity);
        }
        Ok(Self {
            capacity,
            forward: HashMap::new(),
            reverse: HashMap::new(),
        })
    }

    pub fn get_or_allocate(&mut self, host: &str) -> Result<Ipv4Addr, DnsError> {
        let host = canonical_host(host)?;
        if let Some(ip) = self.forward.get(&host) {
            return Ok(*ip);
        }
        if self.forward.len() == self.capacity {
            return Err(DnsError::Exhausted);
        }
        let index = self.forward.len();
        let ip = Ipv4Addr::new(127, 8, (index / 254) as u8, (index % 254 + 1) as u8);
        self.forward.insert(host.clone(), ip);
        self.reverse.insert(ip, host);
        Ok(ip)
    }

    pub fn lookup(&self, host: &str) -> Option<Ipv4Addr> {
        canonical_host(host)
            .ok()
            .and_then(|host| self.forward.get(&host).copied())
    }
    pub fn reverse(&self, ip: Ipv4Addr) -> Option<&str> {
        self.reverse.get(&ip).map(String::as_str)
    }
    pub fn len(&self) -> usize {
        self.forward.len()
    }
    pub fn is_empty(&self) -> bool {
        self.forward.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub transaction_id: u16,
    pub flags: u16,
    pub host: String,
    pub qtype: u16,
    pub qclass: u16,
    pub edns_udp_size: Option<u16>,
}

fn word(packet: &[u8], offset: usize) -> Result<u16, DnsError> {
    let bytes = packet
        .get(offset..offset + 2)
        .ok_or(DnsError::MalformedQuery("truncated field"))?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

/// Returns the uncompressed name and the next offset in the original record.
/// Pointer traversal is bounded, backward-only, and rejects cycles. Labels and
/// the expanded name obey the 63-byte/255-byte DNS limits.
pub fn decode_name(packet: &[u8], start: usize) -> Result<(String, usize), DnsError> {
    let mut position = start;
    let mut next = None;
    let mut visited = Vec::new();
    let mut labels = Vec::new();
    let mut expanded_len = 1;
    loop {
        if visited.len() >= 128 || visited.contains(&position) {
            return Err(DnsError::MalformedQuery(
                "compression cycle or traversal limit",
            ));
        }
        visited.push(position);
        let length = *packet
            .get(position)
            .ok_or(DnsError::MalformedQuery("truncated name"))?;
        if length & 0xc0 == 0xc0 {
            let low = *packet
                .get(position + 1)
                .ok_or(DnsError::MalformedQuery("truncated pointer"))?;
            let target = (usize::from(length & 0x3f) << 8) | usize::from(low);
            if target < 12 || target >= position || target >= packet.len() {
                return Err(DnsError::MalformedQuery("invalid compression pointer"));
            }
            next.get_or_insert(position + 2);
            position = target;
            continue;
        }
        if length & 0xc0 != 0 {
            return Err(DnsError::MalformedQuery("reserved label encoding"));
        }
        position += 1;
        if length == 0 {
            break;
        }
        expanded_len += usize::from(length) + 1;
        if expanded_len > 255 {
            return Err(DnsError::MalformedQuery("expanded name exceeds 255 bytes"));
        }
        let label = packet
            .get(position..position + usize::from(length))
            .ok_or(DnsError::MalformedQuery("truncated label"))?;
        if !label
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(*b, b'-' | b'_'))
        {
            return Err(DnsError::UnsupportedName);
        }
        labels.push(std::str::from_utf8(label).map_err(|_| DnsError::UnsupportedName)?);
        position += usize::from(length);
    }
    Ok((
        if labels.is_empty() {
            ".".into()
        } else {
            labels.join(".")
        },
        next.unwrap_or(position),
    ))
}

/// Parses a single standard IN question and an optional EDNS(0) OPT record.
/// Unsupported queries are explicit errors, never silently treated as A.
pub fn parse_query(packet: &[u8]) -> Result<DnsQuestion, DnsError> {
    if packet.len() < 12 || packet.len() > 65_535 {
        return Err(DnsError::MalformedQuery("invalid packet size"));
    }
    let flags = word(packet, 2)?;
    if flags & !0x0130 != 0 {
        return Err(DnsError::MalformedQuery("unsupported query flags/opcode"));
    }
    if word(packet, 4)? != 1
        || word(packet, 6)? != 0
        || word(packet, 8)? != 0
        || word(packet, 10)? > 1
    {
        return Err(DnsError::MalformedQuery("invalid record counts"));
    }
    let (host, mut offset) = decode_name(packet, 12)?;
    let qtype = word(packet, offset)?;
    let qclass = word(packet, offset + 2)?;
    if qtype == 0 {
        return Err(DnsError::MalformedQuery("zero query type"));
    }
    if qclass != 1 {
        return Err(DnsError::UnsupportedClass(qclass));
    }
    offset += 4;
    let mut edns_udp_size = None;
    if word(packet, 10)? == 1 {
        let (name, end) = decode_name(packet, offset)?;
        offset = end;
        let kind = word(packet, offset)?;
        if kind != 41 {
            return Err(DnsError::UnsupportedAdditional(kind));
        }
        if name != "." {
            return Err(DnsError::MalformedQuery("OPT name must be root"));
        }
        edns_udp_size = Some(word(packet, offset + 2)?.max(512));
        let ttl = packet
            .get(offset + 4..offset + 8)
            .ok_or(DnsError::MalformedQuery("truncated OPT TTL"))?;
        if ttl[0] != 0 || ttl[1] != 0 || word(packet, offset + 6)? & !0x8000 != 0 {
            return Err(DnsError::MalformedQuery("unsupported EDNS version/flags"));
        }
        let length = usize::from(word(packet, offset + 8)?);
        offset += 10;
        let end = offset + length;
        if end > packet.len() {
            return Err(DnsError::MalformedQuery("truncated EDNS options"));
        }
        while offset < end {
            if end - offset < 4 {
                return Err(DnsError::MalformedQuery("truncated EDNS option"));
            }
            let length = usize::from(word(packet, offset + 2)?);
            offset += 4;
            if length > end - offset {
                return Err(DnsError::MalformedQuery("invalid EDNS option length"));
            }
            offset += length;
        }
    }
    if offset != packet.len() {
        return Err(DnsError::MalformedQuery("trailing packet bytes"));
    }
    Ok(DnsQuestion {
        transaction_id: word(packet, 0)?,
        flags,
        host,
        qtype,
        qclass,
        edns_udp_size,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum DnsDecision {
    /// Caller must perform forwarding using the requested mode, or send an
    /// explicit SERVFAIL if that backend is unavailable. Never ignore it.
    Forward {
        question: DnsQuestion,
        mode: DnsMode,
    },
    Answer(Vec<u8>),
}

#[derive(Debug)]
pub struct DnsResolver {
    pub policy: DnsPolicy,
    pub mappings: FakeIpMap,
    pub ttl_seconds: u32,
}

impl DnsResolver {
    pub fn new(policy: DnsPolicy, mappings: FakeIpMap, ttl_seconds: u32) -> Self {
        Self {
            policy,
            mappings,
            ttl_seconds,
        }
    }

    pub fn handle_query(&mut self, packet: &[u8]) -> Result<DnsDecision, DnsError> {
        let question = parse_query(packet)?;
        // The DNS root has no usable proxy hostname; preserve the query.
        let mode = if question.host == "." {
            DnsMode::Local
        } else {
            self.policy.mode_for_host(&question.host)?
        };
        if mode == DnsMode::Local {
            return Ok(DnsDecision::Forward { question, mode });
        }
        if question.qtype != 1 {
            // BlockNonATypes is inferred to mean a NOERROR/NODATA response.
            // Disabling it exposes an explicit remote forwarding requirement.
            if self.policy.options.block_non_a_types {
                return Ok(DnsDecision::Answer(build_response(
                    &question,
                    None,
                    self.ttl_seconds,
                    0,
                )));
            }
            return Ok(DnsDecision::Forward { question, mode });
        }
        let ip = self.mappings.get_or_allocate(&question.host)?;
        Ok(DnsDecision::Answer(build_response(
            &question,
            Some(ip),
            self.ttl_seconds,
            0,
        )))
    }

    /// Always emits an explicit decision, including FORMERR/NOTIMP/SERVFAIL.
    pub fn handle_datagram(&mut self, packet: &[u8]) -> DnsDecision {
        match self.handle_query(packet) {
            Ok(decision) => decision,
            Err(error) => {
                let rcode = match error {
                    DnsError::Exhausted => 2,
                    DnsError::UnsupportedClass(_)
                    | DnsError::UnsupportedAdditional(_)
                    | DnsError::UnsupportedName => 4,
                    _ => 1,
                };
                DnsDecision::Answer(match parse_query(packet) {
                    Ok(question) => build_response(&question, None, 0, rcode),
                    Err(_) => error_response(packet, rcode),
                })
            }
        }
    }
}

/// Builds a minimal DNS error for an unparseable packet. The transaction ID is
/// preserved whenever present. `rcode` is limited to the standard four bits.
pub fn error_response(packet: &[u8], rcode: u8) -> Vec<u8> {
    let mut response = vec![0; 12];
    if packet.len() >= 2 {
        response[..2].copy_from_slice(&packet[..2]);
    }
    response[2] = 0x80 | (packet.get(2).copied().unwrap_or(0) & 1);
    response[3] = rcode & 15;
    response
}

fn build_response(
    question: &DnsQuestion,
    address: Option<Ipv4Addr>,
    ttl: u32,
    rcode: u8,
) -> Vec<u8> {
    let mut response = Vec::new();
    response.extend(question.transaction_id.to_be_bytes());
    response.extend((0x8080 | (question.flags & 0x0110) | u16::from(rcode & 15)).to_be_bytes());
    response.extend(1u16.to_be_bytes());
    response.extend(u16::from(address.is_some()).to_be_bytes());
    response.extend([0, 0]);
    response.extend(u16::from(question.edns_udp_size.is_some()).to_be_bytes());
    if question.host != "." {
        for label in question.host.split('.') {
            response.push(label.len() as u8);
            response.extend(label.as_bytes());
        }
    }
    response.push(0);
    response.extend(question.qtype.to_be_bytes());
    response.extend(question.qclass.to_be_bytes());
    if let Some(ip) = address {
        response.extend([0xc0, 12, 0, 1, 0, 1]);
        response.extend(ttl.to_be_bytes());
        response.extend([0, 4]);
        response.extend(ip.octets());
    }
    if let Some(size) = question.edns_udp_size {
        response.extend([0, 0, 41]);
        response.extend(size.to_be_bytes());
        response.extend([0; 6]);
    }
    response
}
