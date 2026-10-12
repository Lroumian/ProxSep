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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConditionKind {
    Application,
    Target,
    Port,
    Interface,
}

impl ConditionKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Application => "Application",
            Self::Target => "Target",
            Self::Port => "Port",
            Self::Interface => "Interface",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConditionTrace {
    pub kind: ConditionKind,
    pub matched: bool,
    pub expected: String,
    pub actual: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleTraceOutcome {
    Disabled,
    DeferredDefault,
    NotEvaluated,
    NotMatched,
    Matched,
    DefaultFallback,
}

impl RuleTraceOutcome {
    pub fn label(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::DeferredDefault => "default deferred while custom rules are evaluated",
            Self::NotEvaluated => "not evaluated after an earlier match",
            Self::NotMatched => "not matched",
            Self::Matched => "matched",
            Self::DefaultFallback => "default fallback",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleTrace {
    pub index: usize,
    pub rule_name: String,
    pub outcome: RuleTraceOutcome,
    pub conditions: Vec<ConditionTrace>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionTrace<'a> {
    pub decision: Decision<'a>,
    pub rules: Vec<RuleTrace>,
}

impl DecisionTrace<'_> {
    pub fn render_text(&self, connection: &Connection) -> String {
        use std::fmt::Write as _;

        let mut output = String::new();
        let _ = writeln!(output, "Connection");
        let _ = writeln!(output, "Process: {}", connection.application);
        if let Some(pid) = connection.pid {
            let _ = writeln!(output, "PID: {pid}");
        }
        let _ = writeln!(output, "Target: {}", connection.target);
        if !connection.resolved_ips.is_empty() {
            let addresses = connection
                .resolved_ips
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(output, "IP: {addresses}");
        }
        let _ = writeln!(output, "Port: {}", connection.port);
        let mut interfaces = connection
            .interfaces
            .iter()
            .filter(|(_, addresses)| !addresses.is_empty())
            .map(|(name, addresses)| {
                format!(
                    "{} ({})",
                    name,
                    addresses
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
            .collect::<Vec<_>>();
        interfaces.sort_unstable();
        if !interfaces.is_empty() {
            let _ = writeln!(output, "Interface: {}", interfaces.join(", "));
        }
        let _ = writeln!(output, "\nEvaluation:\n");
        for rule in &self.rules {
            let _ = writeln!(output, "Rule #{} {}", rule.index + 1, rule.rule_name);
            match rule.outcome {
                RuleTraceOutcome::Matched => {
                    for condition in &rule.conditions {
                        render_condition(&mut output, condition);
                    }
                    let _ = writeln!(output, "\n=> MATCHED\n");
                }
                RuleTraceOutcome::NotMatched => {
                    for condition in &rule.conditions {
                        render_condition(&mut output, condition);
                    }
                    let _ = writeln!(output);
                }
                RuleTraceOutcome::DefaultFallback => {
                    let _ = writeln!(output, "  ✓ Default fallback\n\n=> MATCHED\n");
                }
                outcome => {
                    let _ = writeln!(output, "  - {}\n", outcome.label());
                }
            }
        }
        let _ = writeln!(output, "Action:");
        let _ = writeln!(output, "{}", action_label(self.decision.action));
        output
    }
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
            .map(|rule| decision_for(rule, connection))
            .unwrap_or(Decision {
                rule_name: "<implicit direct>",
                action: &IMPLICIT_DIRECT,
                interface_id: None,
            })
    }

    /// Explain the same ordered decision made by [`Self::decide`] without
    /// adding allocations to the normal routing path.
    pub fn trace(&self, connection: &Connection) -> DecisionTrace<'a> {
        let mut traces = Vec::with_capacity(self.rules.len());
        let mut matched = None;
        for (index, rule) in self.rules.iter().enumerate() {
            let (outcome, conditions) = if matched.is_some() {
                (RuleTraceOutcome::NotEvaluated, Vec::new())
            } else if !rule.enabled {
                (RuleTraceOutcome::Disabled, Vec::new())
            } else if rule.name == "Default" {
                (RuleTraceOutcome::DeferredDefault, Vec::new())
            } else {
                let conditions = trace_conditions(rule, connection);
                if conditions.iter().all(|condition| condition.matched) {
                    matched = Some(rule);
                    (RuleTraceOutcome::Matched, conditions)
                } else {
                    (RuleTraceOutcome::NotMatched, conditions)
                }
            };
            traces.push(RuleTrace {
                index,
                rule_name: rule.name.clone(),
                outcome,
                conditions,
            });
        }

        if matched.is_none()
            && let Some(default_index) = self
                .rules
                .iter()
                .position(|rule| rule.enabled && rule.name == "Default")
        {
            matched = Some(&self.rules[default_index]);
            traces[default_index].outcome = RuleTraceOutcome::DefaultFallback;
        }

        let decision = matched.map_or(
            Decision {
                rule_name: "<implicit direct>",
                action: &IMPLICIT_DIRECT,
                interface_id: None,
            },
            |rule| decision_for(rule, connection),
        );
        DecisionTrace {
            decision,
            rules: traces,
        }
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

fn decision_for<'a>(rule: &'a Rule, connection: &Connection) -> Decision<'a> {
    Decision {
        rule_name: &rule.name,
        action: &rule.action,
        interface_id: connection
            .interfaces
            .get(&rule.interface_id)
            .filter(|ips| !ips.is_empty())
            .map(|_| rule.interface_id.as_str()),
    }
}

fn trace_conditions(rule: &Rule, connection: &Connection) -> Vec<ConditionTrace> {
    let active_interface = connection
        .interfaces
        .get(&rule.interface_id)
        .filter(|addresses| !addresses.is_empty());
    let interface_required = rule.skip_if_interface_down && !rule.interface_id.is_empty();
    vec![
        ConditionTrace {
            kind: ConditionKind::Application,
            matched: matches_application(&rule.applications, connection),
            expected: pattern_label(&rule.applications),
            actual: connection.pid.map_or_else(
                || format!("{} (PID unavailable)", connection.application),
                |pid| format!("{} (PID {pid})", connection.application),
            ),
        },
        ConditionTrace {
            kind: ConditionKind::Target,
            matched: matches_targets(&rule.targets, connection),
            expected: pattern_label(&rule.targets),
            actual: target_label(connection),
        },
        ConditionTrace {
            kind: ConditionKind::Port,
            matched: matches_port_list(&rule.ports, connection.port),
            expected: pattern_label(&rule.ports),
            actual: connection.port.to_string(),
        },
        ConditionTrace {
            kind: ConditionKind::Interface,
            matched: !interface_required || active_interface.is_some(),
            expected: if rule.interface_id.is_empty() {
                "*".into()
            } else if interface_required {
                format!("{} available", rule.interface_id)
            } else {
                format!("{} (availability optional)", rule.interface_id)
            },
            actual: active_interface.map_or_else(
                || {
                    if rule.interface_id.is_empty() {
                        "not constrained".into()
                    } else {
                        format!("{} unavailable", rule.interface_id)
                    }
                },
                |addresses| {
                    format!(
                        "{} available ({})",
                        rule.interface_id,
                        addresses
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                },
            ),
        },
    ]
}

fn pattern_label(value: &str) -> String {
    if value.trim().is_empty() {
        "*".into()
    } else {
        value.into()
    }
}

fn target_label(connection: &Connection) -> String {
    if connection.resolved_ips.is_empty() {
        return connection.target.clone();
    }
    format!(
        "{} ({})",
        connection.target,
        connection
            .resolved_ips
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    )
}

fn render_condition(output: &mut String, condition: &ConditionTrace) {
    use std::fmt::Write as _;

    let marker = if condition.matched { '✓' } else { '✗' };
    let result = if condition.matched {
        "matched"
    } else {
        "mismatch"
    };
    let _ = writeln!(output, "  {marker} {} {result}", condition.kind.label());
    if !condition.matched {
        let _ = writeln!(output, "    Expected: {}", condition.expected);
        let _ = writeln!(output, "    Actual: {}", condition.actual);
    }
}

fn action_label(action: &Action) -> String {
    match action {
        Action::Direct => "Direct".into(),
        Action::Block => "Block".into(),
        Action::Proxy(proxy) => format!("Proxy -> {proxy}"),
        Action::Chain(chain) => format!("Chain -> {chain}"),
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
