use proxsep_protocol::socks5::{self, Socks5Error, UdpAssociation};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TIMEOUT: Duration = Duration::from_secs(2);

async fn accept_association(
    listener: tokio::net::TcpListener,
    relay_port: u16,
) -> tokio::net::TcpStream {
    let (mut control, _) = listener.accept().await.unwrap();
    let mut greeting = [0; 3];
    control.read_exact(&mut greeting).await.unwrap();
    control.write_all(&[5, 0]).await.unwrap();
    let mut request = [0; 10];
    control.read_exact(&mut request).await.unwrap();
    assert_eq!(request[1], 3);
    let mut response = vec![5, 0, 0, 1, 127, 0, 0, 1];
    response.extend(relay_port.to_be_bytes());
    control.write_all(&response).await.unwrap();
    control
}

#[tokio::test]
async fn owning_association_relays_and_holds_control_socket() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_address = relay.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let mut control = accept_association(listener, relay_address.port()).await;
        let mut buffer = [0; 256];
        let (length, client) = relay.recv_from(&mut buffer).await.unwrap();
        let datagram = socks5::decode_udp_datagram(&buffer[..length]).unwrap();
        assert_eq!(datagram.destination.host, "example.com");
        assert_eq!(datagram.payload, b"query");
        // A third-party sender must not inject a reply into the connected UDP socket.
        let foreign = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        foreign
            .send_to(
                &socks5::encode_udp_datagram("192.0.2.99", 53, b"spoofed").unwrap(),
                client,
            )
            .await
            .unwrap();
        relay
            .send_to(
                &socks5::encode_udp_datagram("192.0.2.1", 53, b"answer").unwrap(),
                client,
            )
            .await
            .unwrap();
        assert_eq!(control.read(&mut buffer).await.unwrap(), 0);
    });
    let mut association = UdpAssociation::connect("127.0.0.1", proxy.port(), None, TIMEOUT)
        .await
        .unwrap();
    assert_eq!(association.relay_addr(), relay_address);
    assert_eq!(
        association
            .send("example.com", 53, b"query", TIMEOUT)
            .await
            .unwrap(),
        5
    );
    let response = association.recv(TIMEOUT).await.unwrap();
    assert_eq!(response.source.host, "192.0.2.1");
    assert_eq!(response.payload, b"answer");
    drop(association);
    peer.await.unwrap();
}

#[tokio::test]
async fn owning_association_detects_control_close() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_port = relay.local_addr().unwrap().port();
    let peer = tokio::spawn(async move {
        drop(accept_association(listener, relay_port).await);
    });
    let mut association = UdpAssociation::connect("127.0.0.1", proxy.port(), None, TIMEOUT)
        .await
        .unwrap();
    peer.await.unwrap();
    assert!(matches!(
        association.recv(TIMEOUT).await,
        Err(Socks5Error::AssociationClosed)
    ));
    assert!(matches!(
        association.send("example.com", 53, b"query", TIMEOUT).await,
        Err(Socks5Error::AssociationClosed)
    ));
}

#[tokio::test]
async fn owning_association_rejects_invalid_relay_port() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        drop(accept_association(listener, 0).await);
    });
    assert!(matches!(
        UdpAssociation::connect("127.0.0.1", proxy.port(), None, TIMEOUT).await,
        Err(Socks5Error::InvalidRelay)
    ));
    peer.await.unwrap();
}

#[tokio::test]
async fn owning_association_rejects_fragment_and_receive_timeout() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = listener.local_addr().unwrap();
    let relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_address = relay.local_addr().unwrap();
    let peer = tokio::spawn(async move {
        let mut control = accept_association(listener, relay_address.port()).await;
        let mut buffer = [0; 256];
        let (_, client) = relay.recv_from(&mut buffer).await.unwrap();
        let mut packet = socks5::encode_udp_datagram("192.0.2.1", 53, b"answer").unwrap();
        packet[2] = 1;
        relay.send_to(&packet, client).await.unwrap();
        assert_eq!(control.read(&mut buffer).await.unwrap(), 0);
    });
    let mut association = UdpAssociation::connect("127.0.0.1", proxy.port(), None, TIMEOUT)
        .await
        .unwrap();
    association
        .send("example.com", 53, b"query", TIMEOUT)
        .await
        .unwrap();
    assert!(matches!(
        association.recv(TIMEOUT).await,
        Err(Socks5Error::FragmentationUnsupported(1))
    ));
    assert!(matches!(
        association.recv(Duration::from_millis(10)).await,
        Err(Socks5Error::Timeout)
    ));
    drop(association);
    peer.await.unwrap();
}
