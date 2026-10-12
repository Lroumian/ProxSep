use std::time::Duration;

use proxsep_protocol::{http_connect, socks4, socks5};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

async fn read_http_request(server: &mut DuplexStream) {
    let mut request = Vec::new();
    while !request.ends_with(b"\r\n\r\n") {
        request.push(server.read_u8().await.unwrap());
    }
}

async fn fragmented_write(server: &mut DuplexStream, bytes: &[u8]) {
    for byte in bytes {
        server.write_all(&[*byte]).await.unwrap();
        tokio::task::yield_now().await;
    }
}

#[test]
fn socks4_and_socks4a_encoding() {
    assert_eq!(
        socks4::connect_request("192.0.2.1", 1080, "id").unwrap(),
        [vec![4, 1, 4, 56, 192, 0, 2, 1], b"id\0".to_vec()].concat()
    );
    assert_eq!(
        socks4::connect_request("example.com", 443, "").unwrap(),
        [vec![4, 1, 1, 187, 0, 0, 0, 1, 0], b"example.com\0".to_vec()].concat()
    );
    assert!(socks4::connect_request("::1", 443, "").is_err());
    assert!(socks4::connect_request("example.com\0evil", 443, "").is_err());
    assert!(socks4::connect_request("example.com", 443, "id\0bad").is_err());
}

#[tokio::test]
async fn socks4_fragmented_reply_preserves_payload_and_rejects_failures() {
    for status in [90, 91, 92, 93] {
        let (mut client, mut server) = tokio::io::duplex(64);
        let peer = tokio::spawn(async move {
            let mut request = [0; 9];
            server.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [4, 1, 0, 80, 127, 0, 0, 1, 0]);
            fragmented_write(&mut server, &[0, status, 0, 80, 127, 0, 0, 1]).await;
            if status == 90 {
                server.write_all(b"payload").await.unwrap();
            }
        });
        let result = socks4::negotiate(&mut client, "127.0.0.1", 80, "").await;
        if status == 90 {
            result.unwrap();
            let mut payload = [0; 7];
            client.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"payload");
        } else {
            assert!(
                matches!(result, Err(socks4::Socks4Error::ConnectRejected(value)) if value == status)
            );
        }
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn socks5_authentication_fragmented_reply_and_payload() {
    let (mut client, mut server) = tokio::io::duplex(64);
    let peer = tokio::spawn(async move {
        let mut greeting = [0; 4];
        server.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 2, 0, 2]);
        fragmented_write(&mut server, &[5, 2]).await;
        let mut auth = [0; 11];
        server.read_exact(&mut auth).await.unwrap();
        assert_eq!(&auth, b"\x01\x05alice\x03pwd");
        fragmented_write(&mut server, &[1, 0]).await;
        let mut request = [0; 18];
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(
            request,
            socks5::connect_request("example.com", 443)
                .unwrap()
                .as_slice()
        );
        fragmented_write(&mut server, &[5, 0, 0, 3, 3, b'f', b'o', b'o', 1, 187]).await;
        server.write_all(b"TLS").await.unwrap();
    });
    let bound = socks5::negotiate_bound(&mut client, "example.com", 443, Some(("alice", "pwd")))
        .await
        .unwrap();
    assert_eq!(
        bound,
        socks5::BoundAddress {
            host: "foo".into(),
            port: 443
        }
    );
    let mut payload = [0; 3];
    client.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"TLS");
    peer.await.unwrap();
}

#[tokio::test]
async fn socks5_auth_failure_and_unadvertised_method() {
    let (mut client, mut server) = tokio::io::duplex(64);
    let peer = tokio::spawn(async move {
        let mut greeting = [0; 4];
        server.read_exact(&mut greeting).await.unwrap();
        server.write_all(&[5, 2]).await.unwrap();
        let mut auth = [0; 5];
        server.read_exact(&mut auth).await.unwrap();
        server.write_all(&[1, 1]).await.unwrap();
    });
    assert!(matches!(
        socks5::negotiate(&mut client, "example.com", 443, Some(("u", "p"))).await,
        Err(socks5::Socks5Error::AuthenticationFailed(1))
    ));
    peer.await.unwrap();
    let (mut client, mut server) = tokio::io::duplex(64);
    let peer = tokio::spawn(async move {
        let mut greeting = [0; 3];
        server.read_exact(&mut greeting).await.unwrap();
        server.write_all(&[5, 2]).await.unwrap();
    });
    assert!(matches!(
        socks5::negotiate(&mut client, "example.com", 443, None).await,
        Err(socks5::Socks5Error::UnsupportedAuth(2))
    ));
    peer.await.unwrap();
}

#[tokio::test]
async fn socks5_empty_credentials_fail_before_network_io() {
    let (mut client, _server) = tokio::io::duplex(64);
    assert!(matches!(
        socks5::negotiate(&mut client, "example.com", 443, Some(("", "p"))).await,
        Err(socks5::Socks5Error::InvalidCredentials)
    ));
}

#[test]
fn udp_roundtrip_and_malformed_frames() {
    for host in ["192.0.2.1", "::1", "example.com"] {
        let bytes = socks5::encode_udp_datagram(host, 53, b"dns").unwrap();
        let packet = socks5::decode_udp_datagram(&bytes).unwrap();
        assert_eq!(
            packet.destination,
            socks5::BoundAddress {
                host: host.into(),
                port: 53
            }
        );
        assert_eq!(packet.payload, b"dns");
        for length in 0..bytes.len() - 3 {
            assert!(socks5::decode_udp_datagram(&bytes[..length]).is_err());
        }
    }
    assert!(socks5::decode_udp_datagram(&[0, 1, 0, 1, 127, 0, 0, 1, 0, 53]).is_err());
    assert!(matches!(
        socks5::decode_udp_datagram(&[0, 0, 1, 1, 127, 0, 0, 1, 0, 53]),
        Err(socks5::Socks5Error::FragmentationUnsupported(1))
    ));
    assert!(socks5::decode_udp_datagram(&[0, 0, 0, 3, 0, 0, 53]).is_err());
}

#[tokio::test]
async fn udp_associate_encodes_command_and_returns_relay() {
    let (mut client, mut server) = tokio::io::duplex(64);
    let peer = tokio::spawn(async move {
        let mut greeting = [0; 3];
        server.read_exact(&mut greeting).await.unwrap();
        server.write_all(&[5, 0]).await.unwrap();
        let mut request = [0; 10];
        server.read_exact(&mut request).await.unwrap();
        assert_eq!(request, [5, 3, 0, 1, 0, 0, 0, 0, 0, 0]);
        server
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 4, 56])
            .await
            .unwrap();
    });
    let bound = socks5::associate_udp(&mut client, "0.0.0.0", 0, None)
        .await
        .unwrap();
    assert_eq!(
        bound,
        socks5::BoundAddress {
            host: "127.0.0.1".into(),
            port: 1080
        }
    );
    peer.await.unwrap();
}

#[tokio::test]
async fn http_interim_fragmented_success_preserves_tunnel_data() {
    let (mut client, mut server) = tokio::io::duplex(256);
    let peer = tokio::spawn(async move {
        read_http_request(&mut server).await;
        fragmented_write(
            &mut server,
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 Tunnel\r\nContent-Length: 100\r\n\r\nTLS",
        )
        .await;
    });
    http_connect::negotiate(&mut client, "example.com", 443, None)
        .await
        .unwrap();
    let mut payload = [0; 3];
    client.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"TLS");
    peer.await.unwrap();
}

#[tokio::test]
async fn http_rejects_bad_headers_and_status_and_reports_denial() {
    for response in [
        b"HTTP/1.1 200 OK\r\nBad Header: x\r\n\r\n".as_slice(),
        b"HTTP/1.1 20 OK\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nMissingColon\r\n\r\n",
        b"HTTP/1.1 101 Switching Protocols\r\n\r\n",
    ] {
        let (mut client, mut server) = tokio::io::duplex(256);
        let peer = tokio::spawn(async move {
            read_http_request(&mut server).await;
            server.write_all(response).await.unwrap();
        });
        assert!(
            http_connect::negotiate(&mut client, "example.com", 443, None)
                .await
                .is_err()
        );
        peer.await.unwrap();
    }
    let (mut client, mut server) = tokio::io::duplex(256);
    let peer = tokio::spawn(async move {
        read_http_request(&mut server).await;
        server
            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
            .await
            .unwrap();
    });
    assert!(matches!(
        http_connect::negotiate(&mut client, "example.com", 443, None).await,
        Err(http_connect::HttpConnectError::ConnectRejected(407))
    ));
    peer.await.unwrap();
}

#[tokio::test]
async fn stalled_handshakes_time_out() {
    let (mut client, _server) = tokio::io::duplex(256);
    assert!(matches!(
        socks5::negotiate_with_timeout(
            &mut client,
            "example.com",
            443,
            None,
            Duration::from_millis(10)
        )
        .await,
        Err(socks5::Socks5Error::Timeout)
    ));
    let (mut client, _server) = tokio::io::duplex(256);
    assert!(matches!(
        http_connect::negotiate_with_timeout(
            &mut client,
            "example.com",
            443,
            None,
            Duration::from_millis(10)
        )
        .await,
        Err(http_connect::HttpConnectError::Timeout)
    ));
    let (mut client, _server) = tokio::io::duplex(256);
    assert!(matches!(
        socks4::negotiate_with_timeout(
            &mut client,
            "example.com",
            443,
            "",
            Duration::from_millis(10)
        )
        .await,
        Err(socks4::Socks4Error::Timeout)
    ));
}

#[tokio::test]
async fn udp_association_loopback_relays_framed_payload() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_address = relay.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (mut control, _) = listener.accept().await.unwrap();
        let mut greeting = [0; 3];
        control.read_exact(&mut greeting).await.unwrap();
        control.write_all(&[5, 0]).await.unwrap();
        let mut request = [0; 10];
        control.read_exact(&mut request).await.unwrap();
        assert_eq!(request[1], 3);
        let mut reply = vec![5, 0, 0, 1, 127, 0, 0, 1];
        reply.extend(relay_address.port().to_be_bytes());
        control.write_all(&reply).await.unwrap();
        let mut buffer = [0; 128];
        let (length, sender) = relay.recv_from(&mut buffer).await.unwrap();
        let packet = socks5::decode_udp_datagram(&buffer[..length]).unwrap();
        assert_eq!(packet.destination.host, "example.com");
        assert_eq!(packet.destination.port, 53);
        assert_eq!(packet.payload, b"query");
        relay
            .send_to(
                &socks5::encode_udp_datagram("192.0.2.1", 53, b"answer").unwrap(),
                sender,
            )
            .await
            .unwrap();
        // The association ends only when the client drops the control stream.
        assert_eq!(control.read(&mut buffer).await.unwrap(), 0);
    });
    let mut control = tokio::net::TcpStream::connect(proxy).await.unwrap();
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let client_address = socket.local_addr().unwrap();
    let bound = socks5::associate_udp_with_timeout(
        &mut control,
        &client_address.ip().to_string(),
        client_address.port(),
        None,
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    socket
        .connect((bound.host.as_str(), bound.port))
        .await
        .unwrap();
    socket
        .send(&socks5::encode_udp_datagram("example.com", 53, b"query").unwrap())
        .await
        .unwrap();
    let mut buffer = [0; 128];
    let length = socket.recv(&mut buffer).await.unwrap();
    let reply = socks5::decode_udp_datagram(&buffer[..length]).unwrap();
    assert_eq!(reply.destination.host, "192.0.2.1");
    assert_eq!(reply.payload, b"answer");
    drop(control);
    peer.await.unwrap();
}

#[tokio::test]
async fn socks5_malformed_bound_addresses_and_truncated_reply() {
    for response in [
        vec![5, 0, 0, 9],
        vec![5, 0, 0, 3, 0],
        vec![5, 0, 0, 3, 1, 0],
        vec![5, 0, 0, 1, 127],
    ] {
        let (mut client, mut server) = tokio::io::duplex(128);
        let peer = tokio::spawn(async move {
            let mut greeting = [0; 3];
            server.read_exact(&mut greeting).await.unwrap();
            server.write_all(&[5, 0]).await.unwrap();
            let mut request = [0; 10];
            server.read_exact(&mut request).await.unwrap();
            server.write_all(&response).await.unwrap();
        });
        assert!(
            socks5::negotiate(&mut client, "127.0.0.1", 80, None)
                .await
                .is_err()
        );
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn http_limits_headers_and_informational_responses() {
    for informational in [false, true] {
        let (mut client, mut server) = tokio::io::duplex(131_072);
        let peer = tokio::spawn(async move {
            read_http_request(&mut server).await;
            if informational {
                server
                    .write_all(&b"HTTP/1.1 100 Continue\r\n\r\n".repeat(32))
                    .await
                    .unwrap();
            } else {
                let response = [
                    b"HTTP/1.1 200 OK\r\nX: ".to_vec(),
                    vec![b'a'; 65_536],
                    b"\r\n\r\n".to_vec(),
                ]
                .concat();
                server.write_all(&response).await.unwrap();
            }
        });
        let result = http_connect::negotiate(&mut client, "example.com", 443, None).await;
        if informational {
            assert!(matches!(
                result,
                Err(http_connect::HttpConnectError::TooManyInformationalResponses)
            ));
        } else {
            assert!(matches!(
                result,
                Err(http_connect::HttpConnectError::HeadersTooLarge)
            ));
        }
        peer.await.unwrap();
    }
}
