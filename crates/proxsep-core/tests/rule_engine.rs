use proxsep_core::profile::{Action, Rule};
use proxsep_core::rules::{Connection, RuleEngine};

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
