//! Local mock HTTP proxies only: synthetic NTLM verifies transport/context
//! sequencing, not server authentication, cryptography or Proxifier parity.
use proxsep_core::{
    profile::{Action, Profile, Proxy},
    rules::Connection,
};
use proxsep_runtime::{Runtime, RuntimeError};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

const LIMIT: Duration = Duration::from_secs(8);
const CLOSE: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: NTLM\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";

fn runtime(address: SocketAddr, credentials: Option<(&str, &str)>) -> std::sync::Arc<Runtime> {
    let mut profile = Profile::default();
    profile.proxies.push(Proxy {
        id: 1,
        protocol: "HTTPS".into(),
        address: address.ip().to_string(),
        port: address.port(),
        username: credentials.map(|(username, _)| username.to_owned()),
        password: credentials.map(|(_, password)| password.to_owned()),
        user_agent: "Runtime reconnect fixture".into(),
        ..Proxy::default()
    });
    profile.rules[0].action = Action::Proxy("1".into());
    Runtime::new(profile)
}

fn destination() -> Connection {
    // Numeric mock target: neither runtime nor test performs external DNS/connect.
    Connection::new("http-reconnect-test", "127.0.0.2", 443)
}

async fn accept(listener: &TcpListener) -> TcpStream {
    timeout(LIMIT, listener.accept()).await.unwrap().unwrap().0
}

async fn request(stream: &mut TcpStream) -> String {
    timeout(LIMIT, async {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            assert!(bytes.len() < 65_536, "mock request exceeds header bound");
            bytes.push(stream.read_u8().await.unwrap());
        }
        let value = String::from_utf8(bytes).unwrap();
        assert!(value.starts_with("CONNECT 127.0.0.2:443 HTTP/1.1\r\n"));
        assert!(value.contains("User-Agent: Runtime reconnect fixture\r\n"));
        value
    })
    .await
    .unwrap()
}

#[cfg(windows)]
fn assert_ntlm_type(request: &str, expected: u32) {
    let value = request
        .lines()
        .find_map(|line| line.strip_prefix("Proxy-Authorization: "))
        .expect("authentication header missing");
    let challenges = proxsep_protocol::sspi::parse_challenges(value).unwrap();
    assert_eq!(challenges.len(), 1);
    assert!(challenges[0].is_scheme(proxsep_protocol::sspi::AuthScheme::Ntlm));
    let token = challenges[0].decode_token().unwrap().unwrap();
    assert!(token.len() >= 12 && &token[..8] == b"NTLMSSP\0");
    assert_eq!(
        u32::from_le_bytes(token[8..12].try_into().unwrap()),
        expected
    );
}

#[cfg(windows)]
fn type2(close: bool) -> String {
    // Fixed, public dummy challenge from the protocol test's 60-byte fixture.
    // Not an external server token, credential capture or crypto verification.
    const TOKEN: &str =
        "TlRMTVNTUAACAAAAAAAAADgAAAABgogAAQIDBAUGBwgAAAAAAAAAAAQABAA4AAAAAAAAAAAAAAAAAAAA";
    format!(
        "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: NTLM {TOKEN}\r\n{}Content-Length: 0\r\n\r\n",
        if close { "Connection: close\r\n" } else { "" }
    )
}

#[cfg(windows)]
async fn finish_ntlm(stream: &mut TcpStream) {
    assert_ntlm_type(&request(stream).await, 1);
    stream.write_all(type2(false).as_bytes()).await.unwrap();
    assert_ntlm_type(&request(stream).await, 3);
    // Same write contains headers and tunneled bytes: negotiation must not eat TLS.
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\nContent-Length: 999\r\n\r\nTLS")
        .await
        .unwrap();
    let mut payload = [0; 4];
    timeout(LIMIT, stream.read_exact(&mut payload))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&payload, b"PING");
    stream.write_all(b"PONG").await.unwrap();
}

#[cfg(windows)]
async fn connected_payload(runtime: &Runtime) {
    let mut stream = timeout(LIMIT, runtime.connect(&destination()))
        .await
        .unwrap()
        .unwrap();
    let mut initial = [0; 3];
    timeout(LIMIT, stream.read_exact(&mut initial))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&initial, b"TLS");
    stream.write_all(b"PING").await.unwrap();
    let mut reply = [0; 4];
    timeout(LIMIT, stream.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"PONG");
    assert_eq!(runtime.events().len(), 1);
    assert_eq!(runtime.events()[0].state, "Open");
}

#[cfg(windows)]
#[tokio::test]
async fn runtime_reconnects_basic_to_fresh_ntlm_and_preserves_tunnel() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let runtime = runtime(
        listener.local_addr().unwrap(),
        Some(("protocol-test", "not-a-real-secret")),
    );
    let peer = tokio::spawn(async move {
        let mut first = accept(&listener).await;
        assert!(
            request(&mut first)
                .await
                .contains("Proxy-Authorization: Basic ")
        );
        first.write_all(CLOSE).await.unwrap();
        drop(first);
        let mut second = accept(&listener).await;
        finish_ntlm(&mut second).await;
    });
    connected_payload(&runtime).await;
    timeout(LIMIT, peer).await.unwrap().unwrap();
}

#[cfg(windows)]
#[tokio::test]
async fn type2_connection_close_discards_context_and_starts_type1_again() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let runtime = runtime(
        listener.local_addr().unwrap(),
        Some(("protocol-test", "not-a-real-secret")),
    );
    let peer = tokio::spawn(async move {
        let mut first = accept(&listener).await;
        request(&mut first).await;
        first.write_all(CLOSE).await.unwrap();
        drop(first);
        let mut second = accept(&listener).await;
        assert_ntlm_type(&request(&mut second).await, 1);
        second.write_all(type2(true).as_bytes()).await.unwrap();
        drop(second);
        // The third connection must not resume with a Type3 for second's context.
        let mut third = accept(&listener).await;
        finish_ntlm(&mut third).await;
    });
    connected_payload(&runtime).await;
    timeout(LIMIT, peer).await.unwrap().unwrap();
}

#[cfg(windows)]
#[tokio::test]
async fn repeated_close_is_limited_to_three_fresh_connections() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let runtime = runtime(
        listener.local_addr().unwrap(),
        Some(("protocol-test", "not-a-real-secret")),
    );
    let peer = tokio::spawn(async move {
        for attempt in 0..3 {
            let mut stream = accept(&listener).await;
            let value = request(&mut stream).await;
            if attempt == 0 {
                assert!(value.contains("Proxy-Authorization: Basic "));
            } else {
                assert_ntlm_type(&value, 1);
            }
            stream.write_all(CLOSE).await.unwrap();
        }
        assert!(
            timeout(Duration::from_millis(200), listener.accept())
                .await
                .is_err()
        );
    });
    let error = timeout(LIMIT, runtime.connect(&destination()))
        .await
        .unwrap()
        .unwrap_err();
    assert!(
        matches!(error, RuntimeError::Proxy(ref message) if message.contains("repeatedly closed"))
    );
    assert_eq!(runtime.events()[0].state, "Failed");
    timeout(LIMIT, peer).await.unwrap().unwrap();
}

#[tokio::test]
async fn unauthenticated_repeated_close_is_also_bounded_on_every_platform() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let runtime = runtime(listener.local_addr().unwrap(), None);
    let peer = tokio::spawn(async move {
        for _ in 0..3 {
            let mut stream = accept(&listener).await;
            assert!(!request(&mut stream).await.contains("Proxy-Authorization:"));
            stream.write_all(CLOSE).await.unwrap();
        }
        assert!(
            timeout(Duration::from_millis(200), listener.accept())
                .await
                .is_err()
        );
    });
    let error = timeout(LIMIT, runtime.connect(&destination()))
        .await
        .unwrap()
        .unwrap_err();
    assert!(
        matches!(error, RuntimeError::Proxy(ref message) if message.contains("repeatedly closed"))
    );
    timeout(LIMIT, peer).await.unwrap().unwrap();
}

#[tokio::test]
async fn no_credentials_never_implicitly_sends_current_user_authentication() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let runtime = runtime(listener.local_addr().unwrap(), None);
    let peer = tokio::spawn(async move {
        let mut stream = accept(&listener).await;
        assert!(!request(&mut stream).await.contains("Proxy-Authorization:"));
        stream
            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: NTLM\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        assert_eq!(
            timeout(LIMIT, stream.read_u8())
                .await
                .unwrap()
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        assert!(
            timeout(Duration::from_millis(200), listener.accept())
                .await
                .is_err()
        );
    });
    let error = timeout(LIMIT, runtime.connect(&destination()))
        .await
        .unwrap()
        .unwrap_err();
    assert!(
        matches!(error, RuntimeError::Proxy(ref message) if message.contains("enabled authentication"))
    );
    timeout(LIMIT, peer).await.unwrap().unwrap();
}

#[cfg(not(windows))]
#[tokio::test]
async fn explicitly_enabled_sspi_reports_unsupported_without_fallback_or_tokens() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let runtime = runtime(listener.local_addr().unwrap(), Some(("", "")));
    let peer = tokio::spawn(async move {
        let mut stream = accept(&listener).await;
        assert!(!request(&mut stream).await.contains("Proxy-Authorization:"));
        stream
            .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: NTLM\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        assert_eq!(
            timeout(LIMIT, stream.read_u8())
                .await
                .unwrap()
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    });
    let error = timeout(LIMIT, runtime.connect(&destination()))
        .await
        .unwrap()
        .unwrap_err();
    assert!(
        matches!(error, RuntimeError::Proxy(ref message) if message.contains("unavailable on this platform"))
    );
    timeout(LIMIT, peer).await.unwrap().unwrap();
}
