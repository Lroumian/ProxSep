use proxsep_core::{profile::Profile, rules::Connection};
use proxsep_runtime::Runtime;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

fn profile(action: &str, proxies: &str, chains: &str) -> Profile {
    Profile::from_xml(&format!(r#"<ProxifierProfile version="102" platform="Windows"><Options><Encryption mode="none"/></Options><ProxyList>{proxies}</ProxyList><ChainList>{chains}</ChainList><RuleList><Rule enabled="true"><Name>Default</Name>{action}</Rule></RuleList></ProxifierProfile>"#)).unwrap()
}

async fn echo() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = socket.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    address
}

#[tokio::test]
async fn direct_and_block_are_enforced_on_live_connections() {
    let address = echo().await;
    let runtime = Runtime::new(profile("<Action type=\"Direct\"/>", "", ""));
    let connection = Connection::new("app.exe", "127.0.0.1", address.port());
    let mut stream = runtime.connect(&connection).await.unwrap();
    stream.write_all(b"hello").await.unwrap();
    let mut reply = [0; 5];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"hello");
    runtime
        .replace_profile(profile("<Action type=\"Block\"/>", "", ""))
        .unwrap();
    assert!(runtime.connect(&connection).await.is_err());
}

#[tokio::test]
async fn local_socks_listener_routes_and_stops_cleanly() {
    let address = echo().await;
    let runtime = Runtime::new(profile("<Action type=\"Direct\"/>", "", ""));
    let handle = runtime
        .start_socks5("127.0.0.1:0", "browser.exe".into())
        .await
        .unwrap();
    let mut client = TcpStream::connect(handle.local_addr()).await.unwrap();
    proxsep_protocol::socks5::negotiate(&mut client, "127.0.0.1", address.port(), None)
        .await
        .unwrap();
    client.write_all(b"ping").await.unwrap();
    let mut reply = [0; 4];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"ping");
    assert!(!runtime.events().is_empty());
    handle.stop().await;
    assert!(TcpStream::connect(handle.local_addr()).await.is_err());
}

#[tokio::test]
async fn redundancy_can_fallback_direct_but_simple_chains_cannot() {
    let address = echo().await;
    let proxies =
        "<Proxy id=\"1\" type=\"SOCKS5\"><Address>127.0.0.1</Address><Port>1</Port></Proxy>";
    let chain = "<Chain id=\"2\" type=\"redundancy\"><Name>fallback</Name><Proxy enabled=\"true\">1</Proxy><RedundancyTryDirect>true</RedundancyTryDirect></Chain>";
    let runtime = Runtime::new(profile("<Action type=\"Chain\">2</Action>", proxies, chain));
    assert!(
        runtime
            .connect(&Connection::new("app.exe", "127.0.0.1", address.port()))
            .await
            .is_ok()
    );
    runtime
        .replace_profile(profile(
            "<Action type=\"Chain\">2</Action>",
            proxies,
            &chain.replace("redundancy", "simple"),
        ))
        .unwrap();
    assert!(
        runtime
            .connect(&Connection::new("app.exe", "127.0.0.1", address.port()))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn loop_prevention_never_overrides_an_explicit_block() {
    let address = echo().await;
    let proxies = format!(
        "<Proxy id=\"1\" type=\"SOCKS5\"><Address>127.0.0.1</Address><Port>{}</Port></Proxy>",
        address.port()
    );
    let runtime = Runtime::new(profile("<Action type=\"Block\"/>", &proxies, ""));
    assert!(
        runtime
            .connect(&Connection::new("app.exe", "127.0.0.1", address.port()))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn old_failures_cannot_poison_replacement_chain() {
    let old = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let new = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let old_port = old.local_addr().unwrap().port();
    let new_port = new.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (mut s, _) = old.accept().await.unwrap();
        let mut hello = [0; 3];
        s.read_exact(&mut hello).await.unwrap();
        ready_tx.send(()).unwrap();
        release_rx.await.unwrap();
        s.write_all(&[5, 255]).await.unwrap();
    });
    let make = |port| {
        profile(
            "<Action type=\"Chain\">2</Action>",
            &format!(
                "<Proxy id=\"1\" type=\"SOCKS5\"><Address>127.0.0.1</Address><Port>{port}</Port></Proxy>"
            ),
            "<Chain id=\"2\" type=\"redundancy\"><Name>failover</Name><Proxy>1</Proxy><RedundancyRecheck>false</RedundancyRecheck></Chain>",
        )
    };
    let runtime = Runtime::new(make(old_port));
    let old_runtime = runtime.clone();
    let old_request = tokio::spawn(async move {
        old_runtime
            .connect(&Connection::new("app", "127.0.0.1", 80))
            .await
    });
    ready_rx.await.unwrap();
    runtime.replace_profile(make(new_port)).unwrap();
    release_tx.send(()).unwrap();
    assert!(old_request.await.unwrap().is_err());
    task.await.unwrap();
    let server = tokio::spawn(async move {
        let (mut s, _) = new.accept().await.unwrap();
        let mut hello = [0; 3];
        s.read_exact(&mut hello).await.unwrap();
        s.write_all(&[5, 0]).await.unwrap();
        let mut request = [0; 10];
        s.read_exact(&mut request).await.unwrap();
        s.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
            .await
            .unwrap();
    });
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        runtime.connect(&Connection::new("app", "127.0.0.1", 80)),
    )
    .await
    .unwrap();
    assert!(result.is_ok(), "replacement proxy was skipped: {result:?}");
    server.await.unwrap();
}

#[tokio::test]
async fn blocked_hostnames_do_not_require_dns() {
    let runtime = Runtime::new(profile("<Action type=\"Block\"/>", "", ""));
    let error = runtime
        .connect(&Connection::new("app", "blocked-host.invalid", 80))
        .await
        .unwrap_err();
    assert!(
        matches!(error, proxsep_runtime::RuntimeError::Blocked),
        "{error}"
    );
}

#[tokio::test]
async fn remote_dns_plain_socks4_is_rejected_without_local_lookup() {
    let address = echo().await;
    let mut p = profile(
        "<Action type=\"Proxy\">1</Action>",
        &format!(
            "<Proxy id=\"1\" type=\"SOCKS4\"><Address>127.0.0.1</Address><Port>{}</Port></Proxy>",
            address.port()
        ),
        "",
    );
    p.options.resolve.auto_mode_detection = false;
    p.options.resolve.via_proxy = true;
    let error = Runtime::new(p)
        .connect(&Connection::new("app", "remote-host.invalid", 80))
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("SOCKS4 cannot resolve a hostname remotely"),
        "{error}"
    );
}

#[tokio::test]
async fn direct_uses_supplied_resolved_addresses() {
    let address = echo().await;
    let mut p = profile("<Action type=\"Direct\"/>", "", "");
    p.options.resolve.auto_mode_detection = false;
    p.options.resolve.via_proxy = true;
    let mut c = Connection::new("app", "already-resolved.invalid", address.port());
    c.resolved_ips = vec!["127.0.0.1".parse().unwrap()];
    assert!(Runtime::new(p).connect(&c).await.is_ok());
}

#[tokio::test]
async fn password_only_encrypted_credentials_are_not_sent() {
    let address = echo().await;
    let mut p = profile(
        "<Action type=\"Proxy\">1</Action>",
        &format!(
            "<Proxy id=\"1\" type=\"SOCKS5\"><Address>127.0.0.1</Address><Port>{}</Port></Proxy>",
            address.port()
        ),
        "",
    );
    p.options.encryption_mode = "account".into();
    p.proxies[0].username = None;
    p.proxies[0].password = Some("opaque-ciphertext".into());
    let error = Runtime::new(p)
        .connect(&Connection::new("app", "127.0.0.1", 80))
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("encrypted PPX credentials"),
        "{error}"
    );
}

#[tokio::test]
async fn stopping_listener_marks_pending_connection_cancelled() {
    let proxy = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = proxy.local_addr().unwrap().port();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut socket, _) = proxy.accept().await.unwrap();
        let mut greeting = [0; 3];
        socket.read_exact(&mut greeting).await.unwrap();
        ready_tx.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    let runtime = Runtime::new(profile(
        "<Action type=\"Proxy\">1</Action>",
        &format!(
            "<Proxy id=\"1\" type=\"SOCKS5\"><Address>127.0.0.1</Address><Port>{port}</Port></Proxy>"
        ),
        "",
    ));
    let handle = runtime
        .start_socks5("127.0.0.1:0", "app".into())
        .await
        .unwrap();
    let mut client = TcpStream::connect(handle.local_addr()).await.unwrap();
    let request = tokio::spawn(async move {
        proxsep_protocol::socks5::negotiate(&mut client, "127.0.0.1", 80, None).await
    });
    ready_rx.await.unwrap();
    handle.stop().await;
    assert!(request.await.unwrap().is_err());
    server.abort();
    assert_eq!(runtime.events()[0].state, "Cancelled");
}

#[tokio::test]
async fn protected_mode_does_not_mistake_plain_username_for_ciphertext() {
    let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = server.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        let (mut s, _) = server.accept().await.unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(s.read_u8().await.unwrap());
        }
        assert!(
            String::from_utf8(header)
                .unwrap()
                .contains("Proxy-Authorization: Basic ")
        );
        s.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
    });
    let mut p = profile(
        "<Action type=\"Proxy\">1</Action>",
        &format!(
            "<Proxy id=\"1\" type=\"HTTPS\"><Address>127.0.0.1</Address><Port>{port}</Port></Proxy>"
        ),
        "",
    );
    p.options.encryption_mode = "basic".into();
    p.proxies[0].username = Some("plain-user".into());
    p.proxies[0].password = Some(String::new());
    let result = Runtime::new(p)
        .connect(&Connection::new("app", "127.0.0.1", 80))
        .await;
    assert!(result.is_ok(), "{result:?}");
    task.await.unwrap();
}

#[tokio::test]
async fn relabeling_protected_password_does_not_bypass_runtime_guard() {
    let address = echo().await;
    let xml = format!(
        r#"<ProxifierProfile version="102"><Options><Encryption mode="basic"/></Options><ProxyList><Proxy id="1" type="SOCKS5"><Address>127.0.0.1</Address><Port>{}</Port><Authentication enabled="true"><Username>user</Username><Password>opaque-carrier</Password></Authentication></Proxy></ProxyList><RuleList><Rule><Name>Default</Name><Action type="Proxy">1</Action></Rule></RuleList></ProxifierProfile>"#,
        address.port()
    );
    let mut p = Profile::from_xml(&xml).unwrap();
    p.options.encryption_mode = "disabled".into();
    let error = Runtime::new(p)
        .connect(&Connection::new("app", "127.0.0.1", 80))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("encrypted PPX"), "{error}");
}
