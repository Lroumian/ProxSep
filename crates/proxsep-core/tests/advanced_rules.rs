use proxsep_core::{
    profile::{Action, Rule},
    rules::{Connection, RuleEngine},
};
fn decides(app: &str, target: &str, c: &Connection) -> bool {
    let rules = [Rule {
        name: "match".into(),
        applications: app.into(),
        targets: target.into(),
        action: Action::Block,
        ..Rule::default()
    }];
    matches!(RuleEngine::new(&rules).decide(c).action, Action::Block)
}
#[test]
fn app_list_accepts_quotes_paths_and_pid() {
    let mut c = Connection::new(r"C:\Program Files\App\app.exe", "host", 443);
    c.pid = Some(321);
    assert!(decides(r#""C:\Program Files\App\app.exe""#, "", &c));
    assert!(decides("pid=321", "", &c));
    assert!(!decides("pid=322", "", &c));
    assert!(!decides(r"D:\other\app.exe", "", &c));
}
#[test]
fn targets_accept_cidr_ranges_and_resolved_addresses() {
    let mut c = Connection::new("app.exe", "api.example.com", 443);
    c.resolved_ips = vec!["10.2.3.4".parse().unwrap()];
    assert!(decides("", "10.0.0.0/8", &c));
    assert!(decides("", "10.2.3.1-10.2.3.8", &c));
    assert!(!decides("", "10.3.0.0/16", &c));
    assert!(decides(
        "",
        "2001:db8::1-2001:db8::ffff",
        &Connection::new("app", "2001:db8::42", 443)
    ));
}
#[test]
fn computer_name_and_unicode_wildcards_work() {
    let mut c = Connection::new("应用.exe", "my-pc", 443);
    c.computer_name = "MY-PC".into();
    assert!(decides("??.exe", "%ComputerName%", &c));
}

#[test]
fn default_is_a_fallback_not_an_ordinary_priority_rule() {
    let rules = [
        Rule {
            name: "Default".into(),
            action: Action::Direct,
            ..Rule::default()
        },
        Rule {
            name: "Block".into(),
            targets: "bad.example".into(),
            action: Action::Block,
            ..Rule::default()
        },
    ];
    assert_eq!(
        RuleEngine::new(&rules)
            .decide(&Connection::new("app", "bad.example", 443))
            .rule_name,
        "Block"
    );
}

#[test]
fn down_interface_skip_does_not_leak_into_the_matching_rule() {
    let rules = [Rule {
        name: "special".into(),
        interface_id: "{DOWN}".into(),
        skip_if_interface_down: true,
        action: Action::Block,
        ..Rule::default()
    }];
    assert_eq!(
        RuleEngine::new(&rules)
            .decide(&Connection::new("app", "127.0.0.1", 80))
            .action,
        &Action::Direct
    );
    let mut c = Connection::new("app", "127.0.0.1", 80);
    c.interfaces
        .insert("{DOWN}".into(), vec!["127.0.0.1".parse().unwrap()]);
    assert_eq!(RuleEngine::new(&rules).decide(&c).action, &Action::Block);
}
