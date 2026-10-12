use crate::profile::{Action, Rule};

static IMPLICIT_DIRECT: Action = Action::Direct;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    pub application: String,
    pub target: String,
    pub port: u16,
    pub pid: Option<u32>,
    pub resolved_ips: Vec<std::net::IpAddr>,
    pub computer_name: String,
    pub interfaces: std::collections::HashMap<String, Vec<std::net::IpAddr>>,
    pub bind_ips: Vec<std::net::IpAddr>,
    pub redirect_records: Vec<u8>,
    /// Original numeric endpoint, including IPv6 scope/flow information.
    pub destination: Option<std::net::SocketAddr>,
}

impl Connection {
    pub fn new(application: impl Into<String>, target: impl Into<String>, port: u16) -> Self {
        Self {
            application: application.into(),
            target: target.into(),
            port,
            pid: None,
            resolved_ips: vec![],
            computer_name: std::env::var("COMPUTERNAME").unwrap_or_default(),
            interfaces: std::collections::HashMap::new(),
            bind_ips: vec![],
            redirect_records: vec![],
            destination: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision<'a> {
    pub rule_name: &'a str,
    pub action: &'a Action,
    pub interface_id: Option<&'a str>,
}

pub struct RuleEngine<'a> {
    rules: &'a [Rule],
}

impl<'a> RuleEngine<'a> {
    pub fn new(rules: &'a [Rule]) -> Self {
        Self { rules }
    }

    pub fn decide(&self, connection: &Connection) -> Decision<'a> {
        self.rules
            .iter()
            .find(|rule| rule.enabled && rule.name != "Default" && matches_rule(rule, connection))
            .or_else(|| {
                self.rules
                    .iter()
                    .find(|rule| rule.enabled && rule.name == "Default")
            })
            .map(|rule| Decision {
                rule_name: &rule.name,
                action: &rule.action,
                interface_id: connection
                    .interfaces
                    .get(&rule.interface_id)
                    .filter(|ips| !ips.is_empty())
                    .map(|_| rule.interface_id.as_str()),
            })
            .unwrap_or(Decision {
                rule_name: "<implicit direct>",
                action: &IMPLICIT_DIRECT,
                interface_id: None,
            })
    }

    /// Resolve a decision only when earlier rules cannot change after DNS.
    /// Applications, ports and interface availability never require target DNS.
    pub fn decide_without_dns(&self, connection: &Connection) -> Option<Decision<'a>> {
        if connection.target.parse::<std::net::IpAddr>().is_ok()
            || !connection.resolved_ips.is_empty()
        {
            return Some(self.decide(connection));
        }
        for rule in self
            .rules
            .iter()
            .filter(|rule| rule.enabled && rule.name != "Default")
        {
            if !matches_non_target_fields(rule, connection) {
                continue;
            }
            if matches_targets(&rule.targets, connection) {
                return Some(Decision {
                    rule_name: &rule.name,
                    action: &rule.action,
                    interface_id: connection
                        .interfaces
                        .get(&rule.interface_id)
                        .filter(|ips| !ips.is_empty())
                        .map(|_| rule.interface_id.as_str()),
                });
            }
            if split_patterns(&rule.targets).any(is_ip_pattern) {
                return None;
            }
        }
        // No target-DNS-dependent earlier rule remains; fallback is definitive.
        Some(self.decide(connection))
    }
}

fn matches_rule(rule: &Rule, connection: &Connection) -> bool {
    matches_non_target_fields(rule, connection) && matches_targets(&rule.targets, connection)
}

fn matches_non_target_fields(rule: &Rule, connection: &Connection) -> bool {
    (!rule.skip_if_interface_down
        || rule.interface_id.is_empty()
        || connection
            .interfaces
            .get(&rule.interface_id)
            .is_some_and(|ips| !ips.is_empty()))
        && matches_application(&rule.applications, connection)
        && matches_port_list(&rule.ports, connection.port)
}

fn is_ip_pattern(pattern: &str) -> bool {
    if pattern.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    if let Some((base, bits)) = pattern.split_once('/') {
        return base.parse::<std::net::IpAddr>().is_ok() && bits.parse::<u32>().is_ok();
    }
    if let Some((start, end)) = pattern.split_once('-') {
        return start.trim().parse::<std::net::IpAddr>().is_ok()
            && end.trim().parse::<std::net::IpAddr>().is_ok();
    }
    false
}

fn matches_application(patterns: &str, connection: &Connection) -> bool {
    if patterns.trim().is_empty() {
        return true;
    }
    let path = &connection.application;
    let file_name = path.rsplit(['\\', '/']).next().unwrap_or(path);
    split_patterns(patterns).any(|pattern| {
        let pattern = pattern.trim_matches('"');
        if let Some(pid) = pattern
            .strip_prefix("pid=")
            .or_else(|| pattern.strip_prefix("PID="))
        {
            return pid.parse::<u32>().ok() == connection.pid && connection.pid.is_some();
        }
        if pattern.contains(['\\', '/']) {
            wildcard_match(pattern, path)
        } else {
            wildcard_match(pattern, file_name)
        }
    })
}

fn matches_targets(patterns: &str, c: &Connection) -> bool {
    if patterns.trim().is_empty() {
        return true;
    }
    split_patterns(patterns).any(|pattern| {
        if pattern.eq_ignore_ascii_case("%ComputerName%") {
            return !c.computer_name.is_empty() && c.target.eq_ignore_ascii_case(&c.computer_name);
        }
        let match_ip = |ip: std::net::IpAddr| {
            if let Some((base, bits)) = pattern.split_once('/') {
                if let (Ok(std::net::IpAddr::V4(base)), Ok(bits), std::net::IpAddr::V4(ip)) =
                    (base.parse::<std::net::IpAddr>(), bits.parse::<u32>(), ip)
                    && bits <= 32
                {
                    let mask = if bits == 0 {
                        0
                    } else {
                        u32::MAX << (32 - bits)
                    };
                    return u32::from(base) & mask == u32::from(ip) & mask;
                }
                return false;
            }
            if let Some((a, b)) = pattern.split_once('-') {
                match (
                    a.trim().parse::<std::net::IpAddr>(),
                    b.trim().parse::<std::net::IpAddr>(),
                    ip,
                ) {
                    (
                        Ok(std::net::IpAddr::V4(a)),
                        Ok(std::net::IpAddr::V4(b)),
                        std::net::IpAddr::V4(ip),
                    ) => return u32::from(a) <= u32::from(ip) && u32::from(ip) <= u32::from(b),
                    (
                        Ok(std::net::IpAddr::V6(a)),
                        Ok(std::net::IpAddr::V6(b)),
                        std::net::IpAddr::V6(ip),
                    ) => return u128::from(a) <= u128::from(ip) && u128::from(ip) <= u128::from(b),
                    _ => {}
                }
            }
            pattern.parse::<std::net::IpAddr>() == Ok(ip)
        };
        c.target.parse::<std::net::IpAddr>().is_ok_and(match_ip)
            || c.resolved_ips.iter().copied().any(match_ip)
            || wildcard_match(pattern, c.target.trim_end_matches('.'))
    })
}

fn split_patterns(value: &str) -> impl Iterator<Item = &str> {
    value
        .split([';', ','])
        .map(str::trim)
        .filter(|part| !part.is_empty())
}

fn matches_port_list(patterns: &str, port: u16) -> bool {
    if patterns.trim().is_empty() || patterns.trim() == "*" {
        return true;
    }
    split_patterns(patterns).any(|part| {
        if part == "*" {
            return true;
        }
        if let Some((start, end)) = part.split_once('-') {
            match (start.trim().parse::<u16>(), end.trim().parse::<u16>()) {
                (Ok(start), Ok(end)) => (start..=end).contains(&port),
                _ => false,
            }
        } else {
            part.parse::<u16>() == Ok(port)
        }
    })
}

pub fn validate_ports(patterns: &str) -> Result<(), String> {
    for p in split_patterns(patterns) {
        if p == "*" {
            continue;
        }
        let valid = if let Some((a, b)) = p.split_once('-') {
            match (a.trim().parse::<u16>(), b.trim().parse::<u16>()) {
                (Ok(a), Ok(b)) => a > 0 && a <= b,
                _ => false,
            }
        } else {
            p.parse::<u16>().is_ok_and(|n| n > 0)
        };
        if !valid {
            return Err(format!("invalid port pattern: {p}"));
        }
    }
    Ok(())
}

pub fn wildcard_match(pattern: &str, value: &str) -> bool {
    let pattern: Vec<_> = pattern.chars().flat_map(char::to_lowercase).collect();
    let value: Vec<_> = value.chars().flat_map(char::to_lowercase).collect();
    let (mut p, mut v, mut star, mut retry) = (0, 0, None, 0);
    while v < value.len() {
        if p < pattern.len() && (pattern[p] == '?' || pattern[p] == value[v]) {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            p += 1;
            retry = v;
        } else if let Some(star_index) = star {
            p = star_index + 1;
            retry += 1;
            v = retry;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == '*' {
        p += 1;
    }
    p == pattern.len()
}
