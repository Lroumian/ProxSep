use proxsep_protocol::{http_connect, socks5};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn socks5_rejects_empty_destination() {
    assert!(socks5::connect_request("", 443).is_err());
}

#[test]
fn http_rejects_invalid_authority() {
    for host in [
        "",
        "example.com injected",
        "example.com/path",
        "[bad]",
        "host\tname",
    ] {
        assert!(http_connect::request(host, 443, None).is_err(), "{host:?}");
    }
}

#[tokio::test]
async fn socks5_rejects_nonzero_reserved_reply_byte() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    let peer = tokio::spawn(async move {
        let mut greeting = [0; 3];
        server.read_exact(&mut greeting).await.unwrap();
        server.write_all(&[5, 0]).await.unwrap();
        let mut request = [0; 10];
        server.read_exact(&mut request).await.unwrap();
        server
            .write_all(&[5, 0, 1, 1, 127, 0, 0, 1, 0, 80])
            .await
            .unwrap();
    });
    assert!(
        socks5::negotiate(&mut client, "127.0.0.1", 80, None)
            .await
            .is_err()
    );
    peer.await.unwrap();
}

#[tokio::test]
async fn http_rejects_non_http_status_line() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    let peer = tokio::spawn(async move {
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(server.read_u8().await.unwrap());
        }
        server.write_all(b"garbage 200 OK\r\n\r\n").await.unwrap();
    });
    assert!(
        http_connect::negotiate(&mut client, "example.com", 443, None)
            .await
            .is_err()
    );
    peer.await.unwrap();
}

#[tokio::test]
async fn http_reports_out_of_range_status_as_malformed() {
    let (mut client, mut server) = tokio::io::duplex(1024);
    let peer = tokio::spawn(async move {
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            request.push(server.read_u8().await.unwrap());
        }
        server
            .write_all(b"HTTP/1.1 999 Invalid\r\n\r\n")
            .await
            .unwrap();
    });
    assert!(matches!(
        http_connect::negotiate(&mut client, "example.com", 443, None).await,
        Err(http_connect::HttpConnectError::MalformedResponse)
    ));
    peer.await.unwrap();
}
