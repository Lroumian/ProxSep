#[cfg(windows)]
use base64::{Engine as _, engine::general_purpose::STANDARD};
use proxsep_protocol::{
    http_auth::{self, AuthConfig, HttpAuthError},
    sspi::{AuthScheme, Credentials},
};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

async fn request<S: AsyncRead + Unpin>(stream: &mut S) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(stream.read_u8().await.unwrap());
    }
    String::from_utf8(bytes).unwrap()
}

fn config() -> AuthConfig<'static> {
    AuthConfig {
        basic_credentials: None,
        integrated_credentials: None,
        preferred_scheme: AuthScheme::Negotiate,
        proxy_host: "proxy.example",
        user_agent: Some("ProxSep test"),
        preemptive_scheme: None,
    }
}

#[cfg(windows)]
fn type2_challenge() -> String {
    let mut challenge = vec![0; 60];
    challenge[..8].copy_from_slice(b"NTLMSSP\0");
    challenge[8..12].copy_from_slice(&2u32.to_le_bytes());
    challenge[16..20].copy_from_slice(&56u32.to_le_bytes());
    challenge[20..24].copy_from_slice(&0x0088_8201u32.to_le_bytes());
    challenge[24..32].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    challenge[40..42].copy_from_slice(&4u16.to_le_bytes());
    challenge[42..44].copy_from_slice(&4u16.to_le_bytes());
    challenge[44..48].copy_from_slice(&56u32.to_le_bytes());
    format!(
        "HTTP/1.1 407 Unauthorized\r\nProxy-Authenticate: NTLM {}\r\nContent-Length: 0\r\n\r\n",
        STANDARD.encode(challenge)
    )
}

#[cfg(windows)]
fn assert_type3(value: &str) {
    let header = value
        .lines()
        .find_map(|line| line.strip_prefix("Proxy-Authorization: NTLM "))
        .unwrap();
    let token = STANDARD.decode(header.trim()).unwrap();
    assert_eq!(&token[..8], b"NTLMSSP\0");
    assert_eq!(u32::from_le_bytes(token[8..12].try_into().unwrap()), 3);
}

#[cfg(windows)]
fn explicit() -> Credentials<'static> {
    Credentials::Explicit {
        username: "protocol-test",
        password: "not-a-real-secret",
        domain: Some("."),
    }
}

#[cfg(windows)]
#[tokio::test]
async fn incomplete_ntlm_cannot_accept_success_after_type1() {
    let (mut client, mut server) = tokio::io::duplex(8192);
    let peer = tokio::spawn(async move {
        assert!(
            request(&mut server)
                .await
                .contains("Proxy-Authorization: NTLM ")
        );
        server
            .write_all(b"HTTP/1.1 200 Established\r\n\r\n")
            .await
            .unwrap();
    });
    let settings = AuthConfig {
        integrated_credentials: Some(explicit()),
        preemptive_scheme: Some(AuthScheme::Ntlm),
        ..config()
    };
    assert!(matches!(
        http_auth::negotiate(
            &mut client,
            "example.com",
            443,
            &settings,
            Duration::from_secs(2)
        )
        .await,
        Err(HttpAuthError::IncompleteAuthentication)
    ));
    peer.await.unwrap();
}

#[cfg(windows)]
#[tokio::test]
async fn connection_close_offers_scheme_for_fresh_tcp_type1_authentication() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await.unwrap();
        assert!(!request(&mut first).await.contains("Proxy-Authorization:"));
        first.write_all(b"HTTP/1.1 407 Unauthorized\r\nProxy-Authenticate: NTLM\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").await.unwrap();
        drop(first);
        let (mut second, _) = listener.accept().await.unwrap();
        assert!(
            request(&mut second)
                .await
                .contains("Proxy-Authorization: NTLM ")
        );
        second
            .write_all(type2_challenge().as_bytes())
            .await
            .unwrap();
        assert_type3(&request(&mut second).await);
        second
            .write_all(b"HTTP/1.1 200 Established\r\n\r\nTLS")
            .await
            .unwrap();
    });
    let mut settings = AuthConfig {
        integrated_credentials: Some(explicit()),
        ..config()
    };
    let mut first = tokio::net::TcpStream::connect(address).await.unwrap();
    let error = http_auth::negotiate(
        &mut first,
        "example.com",
        443,
        &settings,
        Duration::from_secs(2),
    )
    .await
    .unwrap_err();
    let HttpAuthError::ReconnectRequired { scheme } = error else {
        panic!("reconnect required")
    };
    assert_eq!(scheme, Some(AuthScheme::Ntlm));
    drop(first);
    settings.preemptive_scheme = scheme;
    let mut second = tokio::net::TcpStream::connect(address).await.unwrap();
    http_auth::negotiate(
        &mut second,
        "example.com",
        443,
        &settings,
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    let mut payload = [0; 3];
    second.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"TLS");
    peer.await.unwrap();
}

#[tokio::test]
async fn successful_connect_includes_user_agent_and_preserves_tunnel_bytes() {
    let (mut client, mut server) = tokio::io::duplex(2048);
    let peer = tokio::spawn(async move {
        let value = request(&mut server).await;
        assert!(value.contains("User-Agent: ProxSep test\r\n"));
        assert!(!value.contains("Proxy-Authorization:"));
        server
            .write_all(b"HTTP/1.1 200 Connection Established\r\nContent-Length: 999\r\n\r\nTLS")
            .await
            .unwrap();
    });
    http_auth::negotiate(
        &mut client,
        "example.com",
        443,
        &config(),
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    let mut payload = [0; 3];
    client.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"TLS");
    peer.await.unwrap();
}

#[tokio::test]
async fn preemptive_basic_success_and_denial_without_integrated_opt_in() {
    let (mut client, mut server) = tokio::io::duplex(2048);
    let peer = tokio::spawn(async move {
        assert!(
            request(&mut server)
                .await
                .contains("Proxy-Authorization: Basic dTpw\r\n")
        );
        server.write_all(b"HTTP/1.1 407 Unauthorized\r\nProxy-Authenticate: NTLM\r\nContent-Length: 0\r\n\r\n").await.unwrap();
    });
    let settings = AuthConfig {
        basic_credentials: Some(("u", "p")),
        ..config()
    };
    assert!(matches!(
        http_auth::negotiate(
            &mut client,
            "example.com",
            443,
            &settings,
            Duration::from_secs(2)
        )
        .await,
        Err(HttpAuthError::NoSupportedAuthentication)
    ));
    peer.await.unwrap();
}

#[cfg(windows)]
#[tokio::test]
async fn ntlm_type1_reuses_connection_after_content_length_body() {
    let (mut client, mut server) = tokio::io::duplex(8192);
    let peer = tokio::spawn(async move {
        request(&mut server).await;
        server.write_all(b"HTTP/1.1 407 Unauthorized\r\nProxy-Authenticate: NTLM\r\nContent-Length: 4\r\n\r\nbody").await.unwrap();
        let value = request(&mut server).await;
        assert!(value.contains("Proxy-Authorization: NTLM "));
        server
            .write_all(type2_challenge().as_bytes())
            .await
            .unwrap();
        assert_type3(&request(&mut server).await);
        server
            .write_all(b"HTTP/1.1 200 Established\r\n\r\nTLS")
            .await
            .unwrap();
    });
    let settings = AuthConfig {
        integrated_credentials: Some(explicit()),
        ..config()
    };
    http_auth::negotiate(
        &mut client,
        "example.com",
        443,
        &settings,
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    let mut payload = [0; 3];
    client.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"TLS");
    peer.await.unwrap();
}

#[cfg(windows)]
#[tokio::test]
async fn ntlm_type1_drains_chunked_body_and_trailers() {
    let (mut client, mut server) = tokio::io::duplex(8192);
    let peer = tokio::spawn(async move {
        request(&mut server).await;
        server.write_all(b"HTTP/1.1 407 Unauthorized\r\nProxy-Authenticate: NTLM\r\nTransfer-Encoding: chunked\r\n\r\n3;x=y\r\nabc\r\n2\r\nde\r\n0\r\nX-Trailer: value\r\n\r\n").await.unwrap();
        assert!(
            request(&mut server)
                .await
                .contains("Proxy-Authorization: NTLM ")
        );
        server
            .write_all(type2_challenge().as_bytes())
            .await
            .unwrap();
        assert_type3(&request(&mut server).await);
        server
            .write_all(b"HTTP/1.1 200 Established\r\n\r\n")
            .await
            .unwrap();
    });
    let settings = AuthConfig {
        integrated_credentials: Some(explicit()),
        ..config()
    };
    http_auth::negotiate(
        &mut client,
        "example.com",
        443,
        &settings,
        Duration::from_secs(2),
    )
    .await
    .unwrap();
    peer.await.unwrap();
}

#[tokio::test]
async fn close_or_missing_framing_requires_reconnect_and_never_resumes_context() {
    for response in [b"HTTP/1.1 407 Unauthorized\r\nProxy-Authenticate: NTLM\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".as_slice(),b"HTTP/1.1 407 Unauthorized\r\nProxy-Authenticate: NTLM\r\n\r\n",b"HTTP/1.0 407 Unauthorized\r\nProxy-Authenticate: NTLM\r\nContent-Length: 0\r\n\r\n"] {
        let (mut client,mut server)=tokio::io::duplex(4096);
        let peer=tokio::spawn(async move {request(&mut server).await;server.write_all(response).await.unwrap();});
        assert!(matches!(http_auth::negotiate(&mut client,"example.com",443,&config(),Duration::from_secs(2)).await,Err(HttpAuthError::ReconnectRequired {..})));
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn conflicting_framing_and_bad_chunks_are_rejected() {
    for response in [b"HTTP/1.1 407 Unauthorized\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nxx".as_slice(),b"HTTP/1.1 407 Unauthorized\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",b"HTTP/1.1 407 Unauthorized\r\nTransfer-Encoding: chunked\r\n\r\nxyz\r\n",b"HTTP/1.1 407 Unauthorized\r\nContent-Length: 1048577\r\n\r\n"] {
        let (mut client,mut server)=tokio::io::duplex(4096);
        let peer=tokio::spawn(async move {request(&mut server).await;server.write_all(response).await.unwrap();});
        assert!(http_auth::negotiate(&mut client,"example.com",443,&config(),Duration::from_secs(2)).await.is_err());peer.await.unwrap();
    }
}

#[tokio::test]
async fn auth_deadline_and_user_agent_injection_are_rejected() {
    let (mut client, _server) = tokio::io::duplex(2048);
    assert!(matches!(
        http_auth::negotiate(
            &mut client,
            "example.com",
            443,
            &config(),
            Duration::from_millis(10)
        )
        .await,
        Err(HttpAuthError::Timeout)
    ));
    let (mut client, _server) = tokio::io::duplex(2048);
    let settings = AuthConfig {
        user_agent: Some("x\r\nInjected: y"),
        ..config()
    };
    assert!(
        http_auth::negotiate(
            &mut client,
            "example.com",
            443,
            &settings,
            Duration::from_millis(10)
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn oversized_outgoing_auth_header_fails_before_any_io() {
    let (mut client, _server) = tokio::io::duplex(16);
    let username = "u".repeat(65_536);
    let settings = AuthConfig {
        basic_credentials: Some((&username, "p")),
        ..config()
    };
    assert!(matches!(
        http_auth::negotiate(
            &mut client,
            "example.com",
            443,
            &settings,
            Duration::from_millis(10)
        )
        .await,
        Err(HttpAuthError::Http(
            proxsep_protocol::http_connect::HttpConnectError::HeadersTooLarge
        ))
    ));
}
