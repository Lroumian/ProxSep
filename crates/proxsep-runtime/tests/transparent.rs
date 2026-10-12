use proxsep_core::profile::Profile;
use proxsep_runtime::Runtime;
use tokio::{io::AsyncReadExt, net::TcpStream};

#[tokio::test]
async fn transparent_listener_rejects_non_wfp_connections_and_stops() {
    let runtime = Runtime::new(Profile::default());
    let handle = runtime.start_transparent("127.0.0.1:0").await.unwrap();
    let mut stream = TcpStream::connect(handle.local_addr()).await.unwrap();
    let mut byte = [0];
    let read = tokio::time::timeout(std::time::Duration::from_secs(2), stream.read(&mut byte))
        .await
        .unwrap();
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "ordinary connections must not become tunnels"
    );
    assert!(runtime.events().is_empty());
    handle.stop().await;
    assert!(TcpStream::connect(handle.local_addr()).await.is_err());
}

#[tokio::test]
async fn transparent_listener_cannot_bind_external_interfaces() {
    assert!(
        Runtime::new(Profile::default())
            .start_transparent("0.0.0.0:0")
            .await
            .is_err()
    );
}
