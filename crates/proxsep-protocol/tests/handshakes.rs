use proxsep_protocol::{http_connect, socks5};

#[test]
fn socks5_greeting_advertises_configured_authentication() {
    assert_eq!(socks5::greeting(false), vec![5, 1, 0]);
    assert_eq!(socks5::greeting(true), vec![5, 2, 0, 2]);
}

#[test]
fn socks5_domain_connect_request_uses_network_byte_order() {
    assert_eq!(
        socks5::connect_request("example.com", 443).unwrap(),
        [
            vec![5, 1, 0, 3, 11],
            b"example.com".to_vec(),
            vec![0x01, 0xbb]
        ]
        .concat()
    );
}

#[test]
fn http_connect_request_has_host_and_optional_basic_auth() {
    let request = http_connect::request("example.com", 443, Some(("alice", "secret"))).unwrap();
    assert!(request.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
    assert!(request.contains("Host: example.com:443\r\n"));
    assert!(request.contains("Proxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n"));
    assert!(request.ends_with("\r\n\r\n"));
}
