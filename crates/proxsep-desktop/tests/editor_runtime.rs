use proxsep_core::{
    profile::{Action, Profile, Rule},
    rules::Connection,
};
use proxsep_desktop::ProfileEditor;
use proxsep_runtime::{Runtime, RuntimeError};

#[tokio::test]
async fn applying_an_edited_rule_order_changes_new_connections() {
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = target.local_addr().unwrap();
    let mut profile = Profile::default();
    profile.rules.insert(
        0,
        Rule {
            name: "Custom direct".into(),
            ..Rule::default()
        },
    );
    profile.rules.insert(
        1,
        Rule {
            name: "Block after default".into(),
            action: Action::Block,
            ..Rule::default()
        },
    );
    let mut editor = ProfileEditor::new(profile);
    let runtime = Runtime::new(editor.profile.clone());
    let connection = Connection::new("desktop-test.exe", address.ip().to_string(), address.port());

    let stream = runtime.connect(&connection).await.unwrap();
    assert!(editor.move_rule(1, -1));
    runtime.replace_profile(editor.profile.clone()).unwrap();
    assert!(matches!(
        runtime.connect(&connection).await,
        Err(RuntimeError::Blocked)
    ));

    let serialized = editor.profile.to_xml().unwrap();
    let restored = Profile::from_xml(&serialized).unwrap();
    assert_eq!(restored.rules[0].action, Action::Block);
    assert_eq!(runtime.events().last().unwrap().rule, "Block after default");
    // Applying an edit affects subsequent connections; existing streams are retained.
    assert!(stream.peer_addr().is_ok());
}
