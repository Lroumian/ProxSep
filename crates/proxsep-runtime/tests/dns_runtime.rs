use proxsep_core::{profile::Profile, rules::Connection};
use proxsep_runtime::Runtime;
use tokio::net::UdpSocket;
fn query(host: &str) -> Vec<u8> {
    let mut b = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in host.split('.') {
        b.push(label.len() as u8);
        b.extend(label.as_bytes());
    }
    b.extend([0, 0, 1, 0, 1]);
    b
}
#[tokio::test]
async fn remote_dns_listener_returns_stable_fake_ip_without_contacting_upstream() {
    let mut p = Profile::default();
    p.options.resolve.auto_mode_detection = false;
    p.options.resolve.via_proxy = true;
    let runtime = Runtime::new(p);
    let handle = runtime
        .start_dns("127.0.0.1:0", "127.0.0.1:1".parse().unwrap())
        .await
        .unwrap();
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    s.connect(handle.local_addr()).await.unwrap();
    s.send(&query("remote.example")).await.unwrap();
    let mut b = [0; 512];
    let n = tokio::time::timeout(std::time::Duration::from_secs(2), s.recv(&mut b))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&b[..2], &[0x12, 0x34]);
    assert_eq!(&b[n - 4..n - 2], &[127, 8]);
    let ip = std::net::Ipv4Addr::new(b[n - 4], b[n - 3], b[n - 2], b[n - 1]);
    assert_eq!(
        runtime.original_hostname(ip).as_deref(),
        Some("remote.example")
    );
    handle.stop().await;
}
#[tokio::test]
async fn unallocated_fake_ip_fails_instead_of_becoming_a_local_connection() {
    let runtime = Runtime::new(Profile::default());
    assert!(
        runtime
            .connect(&Connection::new("app", "127.8.1.1", 80))
            .await
            .is_err()
    );
}
