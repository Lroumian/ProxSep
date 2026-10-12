use proxsep_core::profile::Profile;
use proxsep_service::{EngineConfig, start_engine};

#[tokio::test]
async fn starting_and_stopping_the_shared_engine_does_not_touch_scm() {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "proxsep-service-test-{}-{nonce}.ppx",
        std::process::id()
    ));
    std::fs::write(&path, Profile::default().to_xml().unwrap()).unwrap();
    let config = EngineConfig {
        profile_path: path.clone(),
        listen: "127.0.0.1:0".parse().unwrap(),
        application: "service-test.exe".into(),
    };
    let listener = start_engine(&config).await.unwrap();
    let address = listener.local_addr();
    let connection = tokio::net::TcpStream::connect(address).await.unwrap();
    listener.stop().await;
    assert!(tokio::net::TcpStream::connect(address).await.is_err());
    drop(connection);
    std::fs::remove_file(path).unwrap();
}
