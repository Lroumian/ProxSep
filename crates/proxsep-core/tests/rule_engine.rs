use proxsep_core::profile::{Action, Rule};
use proxsep_core::rules::{ConditionKind, Connection, RuleEngine, RuleTraceOutcome};

fn rule(name: &str, applications: &str, targets: &str, ports: &str, action: Action) -> Rule {
    Rule {
        enabled: true,
        name: name.into(),
        applications: applications.into(),
        targets: targets.into(),
        ports: ports.into(),
        action,
        ..Rule::default()
    }
}

#[test]
fn first_enabled_matching_rule_wins() {
    let rules = vec![
        rule(
            "Browser",
            "firefox.exe; chrome.exe",
            "*.example.com",
            "443",
            Action::Proxy("corp".into()),
        ),
        rule("Default", "", "", "", Action::Direct),
    ];
    let engine = RuleEngine::new(&rules);
    let connection = Connection::new(
        "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
        "api.example.com",
        443,
    );

    assert_eq!(engine.decide(&connection).rule_name, "Browser");
    assert_eq!(
        engine.decide(&connection).action,
        &Action::Proxy("corp".into())
    );
}

#[test]
fn disabled_rules_and_non_matching_ports_are_skipped() {
    let mut blocked = rule("Blocked", "*", "bad.example", "80, 443", Action::Block);
    blocked.enabled = false;
    let rules = vec![
        blocked,
        rule("SSH", "ssh.exe", "*", "22-23", Action::Proxy("ssh".into())),
        rule("Default", "", "", "", Action::Direct),
    ];
    let engine = RuleEngine::new(&rules);

    assert_eq!(
        engine
            .decide(&Connection::new("ssh.exe", "bad.example", 24))
            .rule_name,
        "Default"
    );
    assert_eq!(
        engine
            .decide(&Connection::new("ssh.exe", "host", 22))
            .rule_name,
        "SSH"
    );
}

#[test]
fn matching_is_ascii_case_insensitive_and_accepts_ipv6() {
    let rules = vec![
        rule(
            "Local",
            "APP.EXE",
            "localhost; ::1; 127.0.0.1",
            "*",
            Action::Direct,
        ),
        rule("Default", "", "", "", Action::Block),
    ];
    let engine = RuleEngine::new(&rules);

    assert_eq!(
        engine
            .decide(&Connection::new("c:\\bin\\app.exe", "::1", 8080))
            .rule_name,
        "Local"
    );
}

#[test]
fn decision_trace_explains_failed_conditions_and_the_winning_rule() {
    let mut disabled = rule("Disabled", "*", "*", "*", Action::Block);
    disabled.enabled = false;
    let mut wrong_port = rule(
        "Game login",
        "Wardogs.exe",
        "*.example.com",
        "80",
        Action::Block,
    );
    wrong_port.interface_id = "Ethernet".into();
    wrong_port.skip_if_interface_down = true;
    let mut winner = rule(
        "Game HTTPS",
        "Wardogs.exe",
        "*.example.com",
        "443",
        Action::Proxy("HK-01".into()),
    );
    winner.interface_id = "Ethernet".into();
    winner.skip_if_interface_down = true;
    let rules = vec![
        disabled,
        wrong_port,
        winner,
        rule("Default", "", "", "", Action::Direct),
    ];
    let mut connection = Connection::new(r"C:\Games\Wardogs\Wardogs.exe", "api.example.com", 443);
    connection.pid = Some(8432);
    connection.resolved_ips = vec!["34.120.1.8".parse().unwrap()];
    connection
        .interfaces
        .insert("Ethernet".into(), vec!["192.0.2.10".parse().unwrap()]);

    let engine = RuleEngine::new(&rules);
    let trace = engine.trace(&connection);
    assert_eq!(trace.decision, engine.decide(&connection));
    assert_eq!(trace.rules[0].outcome, RuleTraceOutcome::Disabled);
    assert_eq!(trace.rules[1].outcome, RuleTraceOutcome::NotMatched);
    let port = trace.rules[1]
        .conditions
        .iter()
        .find(|condition| condition.kind == ConditionKind::Port)
        .unwrap();
    assert!(!port.matched);
    assert_eq!(port.expected, "80");
    assert_eq!(port.actual, "443");
    assert_eq!(trace.rules[2].outcome, RuleTraceOutcome::Matched);
    assert!(
        trace.rules[2]
            .conditions
            .iter()
            .all(|condition| condition.matched)
    );
    assert_eq!(trace.rules[3].outcome, RuleTraceOutcome::NotEvaluated);

    let text = trace.render_text(&connection);
    assert!(text.contains("PID: 8432"));
    assert!(text.contains("IP: 34.120.1.8"));
    assert!(text.contains("Interface: Ethernet"));
    assert!(text.contains("Rule #2 Game login"));
    assert!(text.contains("Expected: 80"));
    assert!(text.contains("Actual: 443"));
    assert!(text.contains("Proxy -> HK-01"));
}

#[test]
fn decision_trace_marks_the_default_fallback_without_treating_it_as_a_normal_rule() {
    let rules = vec![
        rule("Default", "ignored.exe", "ignored", "1", Action::Direct),
        rule("SSH", "ssh.exe", "*", "22", Action::Block),
    ];
    let connection = Connection::new("browser.exe", "example.com", 443);

    let trace = RuleEngine::new(&rules).trace(&connection);
    assert_eq!(trace.decision.rule_name, "Default");
    assert_eq!(trace.rules[0].outcome, RuleTraceOutcome::DefaultFallback);
    assert!(trace.rules[0].conditions.is_empty());
    assert_eq!(trace.rules[1].outcome, RuleTraceOutcome::NotMatched);

    let custom = RuleEngine::new(&rules).trace(&Connection::new("ssh.exe", "host", 22));
    assert_eq!(custom.decision.rule_name, "SSH");
    assert_eq!(custom.rules[0].outcome, RuleTraceOutcome::DeferredDefault);
    assert_eq!(custom.rules[1].outcome, RuleTraceOutcome::Matched);
}
