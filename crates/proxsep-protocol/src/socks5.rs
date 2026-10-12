//! SOCKS5 client framing and negotiation (RFC 1928 and RFC 1929).
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, thiserror::Error)]
pub enum Socks5Error {
    #[error("host name is longer than 255 bytes")]
    HostTooLong,
    #[error("destination host is empty or contains forbidden characters")]
    InvalidHost,
    #[error("credentials are longer than 255 bytes")]
    CredentialsTooLong,
    #[error("SOCKS5 username and password must each contain 1 to 255 bytes")]
    InvalidCredentials,
    #[error("proxy selected unsupported authentication method {0:#04x}")]
    UnsupportedAuth(u8),
    #[error("proxy authentication failed with status {0:#04x}")]
    AuthenticationFailed(u8),
    #[error("SOCKS5 proxy rejected the request with status {0:#04x}")]
    ConnectRejected(u8),
    #[error("malformed SOCKS5 response or datagram")]
    MalformedResponse,
    #[error("SOCKS5 UDP fragmentation is not supported (FRAG={0:#04x})")]
    FragmentationUnsupported(u8),
    #[error("UDP packet exceeds the maximum portable datagram size")]
    DatagramTooLarge,
    #[error("SOCKS5 proxy returned an invalid UDP relay endpoint")]
    InvalidRelay,
    #[error("SOCKS5 UDP control connection is closed")]
    AssociationClosed,
    #[error("proxy handshake timed out")]
    Timeout,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundAddress {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, PartialEq, Eq)]
pub struct UdpDatagram<'a> {
    pub destination: BoundAddress,
    pub payload: &'a [u8],
}

pub fn greeting(with_password: bool) -> Vec<u8> {
    if with_password {
        vec![5, 2, 0, 2]
    } else {
        vec![5, 1, 0]
    }
}

fn address_bytes(host: &str, port: u16) -> Result<Vec<u8>, Socks5Error> {
    if host.is_empty() || host.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(Socks5Error::InvalidHost);
    }
    let mut address = Vec::new();
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            address.push(1);
            address.extend(ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            address.push(4);
            address.extend(ip.octets());
        }
        Err(_) => {
            let length = u8::try_from(host.len()).map_err(|_| Socks5Error::HostTooLong)?;
            address.extend([3, length]);
            address.extend(host.as_bytes());
        }
    }
    address.extend(port.to_be_bytes());
    Ok(address)
}

pub fn connect_request(host: &str, port: u16) -> Result<Vec<u8>, Socks5Error> {
    command_request(1, host, port)
}
pub fn udp_associate_request(host: &str, port: u16) -> Result<Vec<u8>, Socks5Error> {
    command_request(3, host, port)
}
fn command_request(command: u8, host: &str, port: u16) -> Result<Vec<u8>, Socks5Error> {
    let mut request = vec![5, command, 0];
    request.extend(address_bytes(host, port)?);
    Ok(request)
}

fn authentication_request(credentials: (&str, &str)) -> Result<Vec<u8>, Socks5Error> {
    if credentials.0.is_empty() || credentials.1.is_empty() {
        return Err(Socks5Error::InvalidCredentials);
    }
    let user_len =
        u8::try_from(credentials.0.len()).map_err(|_| Socks5Error::CredentialsTooLong)?;
    let pass_len =
        u8::try_from(credentials.1.len()).map_err(|_| Socks5Error::CredentialsTooLong)?;
    let mut request = vec![1, user_len];
    request.extend(credentials.0.as_bytes());
    request.push(pass_len);
    request.extend(credentials.1.as_bytes());
    Ok(request)
}

pub async fn negotiate<S>(
    stream: &mut S,
    host: &str,
    port: u16,
    credentials: Option<(&str, &str)>,
) -> Result<(), Socks5Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    negotiate_bound(stream, host, port, credentials)
        .await
        .map(|_| ())
}

pub async fn negotiate_bound<S>(
    stream: &mut S,
    host: &str,
    port: u16,
    credentials: Option<(&str, &str)>,
) -> Result<BoundAddress, Socks5Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    negotiate_command(stream, 1, host, port, credentials).await
}

/// Keep `stream` open throughout the UDP association. The reply is the relay endpoint.
pub async fn associate_udp<S>(
    stream: &mut S,
    client_host: &str,
    client_port: u16,
    credentials: Option<(&str, &str)>,
) -> Result<BoundAddress, Socks5Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    negotiate_command(stream, 3, client_host, client_port, credentials).await
}

async fn negotiate_command<S>(
    stream: &mut S,
    command: u8,
    host: &str,
    port: u16,
    credentials: Option<(&str, &str)>,
) -> Result<BoundAddress, Socks5Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Validate everything before sending the first byte.
    let request = command_request(command, host, port)?;
    let auth = credentials.map(authentication_request).transpose()?;
    stream.write_all(&greeting(credentials.is_some())).await?;
    stream.flush().await?;
    let mut selection = [0; 2];
    stream.read_exact(&mut selection).await?;
    if selection[0] != 5 {
        return Err(Socks5Error::MalformedResponse);
    }
    match selection[1] {
        0 => {}
        2 => {
            stream
                .write_all(auth.as_ref().ok_or(Socks5Error::UnsupportedAuth(2))?)
                .await?;
            stream.flush().await?;
            let mut response = [0; 2];
            stream.read_exact(&mut response).await?;
            if response[0] != 1 {
                return Err(Socks5Error::MalformedResponse);
            }
            if response[1] != 0 {
                return Err(Socks5Error::AuthenticationFailed(response[1]));
            }
        }
        method => return Err(Socks5Error::UnsupportedAuth(method)),
    }
    stream.write_all(&request).await?;
    stream.flush().await?;
    read_reply(stream).await
}

async fn read_reply<S: AsyncRead + Unpin>(stream: &mut S) -> Result<BoundAddress, Socks5Error> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != 5 || header[2] != 0 {
        return Err(Socks5Error::MalformedResponse);
    }
    if header[1] != 0 {
        return Err(Socks5Error::ConnectRejected(header[1]));
    }
    let host = match header[3] {
        1 => {
            let mut bytes = [0; 4];
            stream.read_exact(&mut bytes).await?;
            Ipv4Addr::from(bytes).to_string()
        }
        4 => {
            let mut bytes = [0; 16];
            stream.read_exact(&mut bytes).await?;
            Ipv6Addr::from(bytes).to_string()
        }
        3 => {
            let length = stream.read_u8().await?;
            if length == 0 {
                return Err(Socks5Error::MalformedResponse);
            }
            let mut bytes = vec![0; usize::from(length)];
            stream.read_exact(&mut bytes).await?;
            decode_domain(&bytes)?
        }
        _ => return Err(Socks5Error::MalformedResponse),
    };
    Ok(BoundAddress {
        host,
        port: stream.read_u16().await?,
    })
}

fn decode_domain(bytes: &[u8]) -> Result<String, Socks5Error> {
    let host = std::str::from_utf8(bytes).map_err(|_| Socks5Error::MalformedResponse)?;
    if host.is_empty() || host.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(Socks5Error::MalformedResponse);
    }
    Ok(host.to_owned())
}

pub fn encode_udp_datagram(host: &str, port: u16, payload: &[u8]) -> Result<Vec<u8>, Socks5Error> {
    let mut packet = vec![0, 0, 0];
    packet.extend(address_bytes(host, port)?);
    if packet.len().saturating_add(payload.len()) > 65_507 {
        return Err(Socks5Error::DatagramTooLarge);
    }
    packet.extend(payload);
    Ok(packet)
}

pub fn decode_udp_datagram(packet: &[u8]) -> Result<UdpDatagram<'_>, Socks5Error> {
    if packet.len() < 4 || packet[0] != 0 || packet[1] != 0 {
        return Err(Socks5Error::MalformedResponse);
    }
    if packet[2] != 0 {
        return Err(Socks5Error::FragmentationUnsupported(packet[2]));
    }
    let (host, end) = match packet[3] {
        1 => {
            let bytes: [u8; 4] = packet
                .get(4..8)
                .ok_or(Socks5Error::MalformedResponse)?
                .try_into()
                .unwrap();
            (Ipv4Addr::from(bytes).to_string(), 8)
        }
        4 => {
            let bytes: [u8; 16] = packet
                .get(4..20)
                .ok_or(Socks5Error::MalformedResponse)?
                .try_into()
                .unwrap();
            (Ipv6Addr::from(bytes).to_string(), 20)
        }
        3 => {
            let length = usize::from(*packet.get(4).ok_or(Socks5Error::MalformedResponse)?);
            let end = 5 + length;
            (
                decode_domain(packet.get(5..end).ok_or(Socks5Error::MalformedResponse)?)?,
                end,
            )
        }
        _ => return Err(Socks5Error::MalformedResponse),
    };
    let port_bytes: [u8; 2] = packet
        .get(end..end + 2)
        .ok_or(Socks5Error::MalformedResponse)?
        .try_into()
        .unwrap();
    Ok(UdpDatagram {
        destination: BoundAddress {
            host,
            port: u16::from_be_bytes(port_bytes),
        },
        payload: &packet[end + 2..],
    })
}

/// On timeout discard the partially negotiated stream; it cannot be resumed.
pub async fn negotiate_with_timeout<S>(
    stream: &mut S,
    host: &str,
    port: u16,
    credentials: Option<(&str, &str)>,
    timeout: Duration,
) -> Result<(), Socks5Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tokio::time::timeout(timeout, negotiate(stream, host, port, credentials))
        .await
        .map_err(|_| Socks5Error::Timeout)?
}

pub async fn associate_udp_with_timeout<S>(
    stream: &mut S,
    host: &str,
    port: u16,
    credentials: Option<(&str, &str)>,
    timeout: Duration,
) -> Result<BoundAddress, Socks5Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tokio::time::timeout(timeout, associate_udp(stream, host, port, credentials))
        .await
        .map_err(|_| Socks5Error::Timeout)?
}

#[derive(Debug, PartialEq, Eq)]
pub struct ReceivedUdpDatagram {
    pub source: BoundAddress,
    pub payload: Vec<u8>,
}

/// An association owns its TCP control connection and a connected UDP socket.
/// The OS discards datagrams from endpoints other than the negotiated relay.
/// Dropping this value closes the TCP connection, ending the association.
#[derive(Debug)]
pub struct UdpAssociation {
    control: tokio::net::TcpStream,
    socket: tokio::net::UdpSocket,
    relay: std::net::SocketAddr,
    closed: bool,
}

impl UdpAssociation {
    /// The deadline covers DNS lookup, TCP connect, and proxy negotiation.
    pub async fn connect(
        proxy_host: &str,
        proxy_port: u16,
        credentials: Option<(&str, &str)>,
        timeout: Duration,
    ) -> Result<Self, Socks5Error> {
        tokio::time::timeout(
            timeout,
            Self::connect_inner(proxy_host, proxy_port, credentials),
        )
        .await
        .map_err(|_| Socks5Error::Timeout)?
    }

    async fn connect_inner(
        proxy_host: &str,
        proxy_port: u16,
        credentials: Option<(&str, &str)>,
    ) -> Result<Self, Socks5Error> {
        credentials.map(authentication_request).transpose()?;
        let mut control = tokio::net::TcpStream::connect((proxy_host, proxy_port)).await?;
        let local_ip = control.local_addr()?.ip();
        let socket = tokio::net::UdpSocket::bind(std::net::SocketAddr::new(local_ip, 0)).await?;
        let local = socket.local_addr()?;
        let bound = associate_udp(
            &mut control,
            &local.ip().to_string(),
            local.port(),
            credentials,
        )
        .await?;
        if bound.port == 0 {
            return Err(Socks5Error::InvalidRelay);
        }
        let relay = if let Ok(ip) = bound.host.parse::<IpAddr>() {
            // A number of deployed SOCKS5 servers use an unspecified address
            // to denote the same host as the TCP peer.
            let ip = if ip.is_unspecified() {
                control.peer_addr()?.ip()
            } else {
                ip
            };
            std::net::SocketAddr::new(ip, bound.port)
        } else {
            tokio::net::lookup_host((bound.host.as_str(), bound.port))
                .await?
                .find(|address| {
                    address.is_ipv4() == local.is_ipv4() && valid_relay_ip(address.ip())
                })
                .ok_or(Socks5Error::InvalidRelay)?
        };
        if relay.is_ipv4() != local.is_ipv4() || !valid_relay_ip(relay.ip()) {
            return Err(Socks5Error::InvalidRelay);
        }
        socket.connect(relay).await?;
        Ok(Self {
            control,
            socket,
            relay,
            closed: false,
        })
    }

    pub fn relay_addr(&self) -> std::net::SocketAddr {
        self.relay
    }
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.socket.local_addr()
    }

    /// Returns the number of payload bytes sent, excluding the SOCKS5 header.
    pub async fn send(
        &mut self,
        host: &str,
        port: u16,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<usize, Socks5Error> {
        if self.closed {
            return Err(Socks5Error::AssociationClosed);
        }
        let packet = encode_udp_datagram(host, port, payload)?;
        let mut byte = [0; 1];
        tokio::time::timeout(timeout, async {
            tokio::select! {
                biased;
                result = self.control.read(&mut byte) => {
                    self.closed = true;
                    match result? { 0 => Err(Socks5Error::AssociationClosed), _ => Err(Socks5Error::MalformedResponse) }
                },
                result = self.socket.send(&packet) => {
                    if result? != packet.len() { return Err(std::io::Error::new(std::io::ErrorKind::WriteZero, "partial UDP send").into()); }
                    Ok(payload.len())
                },
            }
        }).await.map_err(|_| Socks5Error::Timeout)?
    }

    /// Rejects malformed packets and unsupported fragments. After a receive
    /// timeout the association stays open and another receive may be attempted.
    pub async fn recv(&mut self, timeout: Duration) -> Result<ReceivedUdpDatagram, Socks5Error> {
        if self.closed {
            return Err(Socks5Error::AssociationClosed);
        }
        let mut packet = vec![0; 65_536];
        let mut byte = [0; 1];
        tokio::time::timeout(timeout, async {
            tokio::select! {
                biased;
                result = self.control.read(&mut byte) => {
                    self.closed = true;
                    match result? { 0 => Err(Socks5Error::AssociationClosed), _ => Err(Socks5Error::MalformedResponse) }
                },
                result = self.socket.recv(&mut packet) => {
                    let length = result?;
                    let decoded = decode_udp_datagram(&packet[..length])?;
                    Ok(ReceivedUdpDatagram { source: decoded.destination, payload: decoded.payload.to_vec() })
                },
            }
        }).await.map_err(|_| Socks5Error::Timeout)?
    }

    pub async fn shutdown(&mut self) -> Result<(), Socks5Error> {
        self.closed = true;
        self.control.shutdown().await?;
        Ok(())
    }
}

fn valid_relay_ip(ip: IpAddr) -> bool {
    !ip.is_unspecified() && !ip.is_multicast() && !matches!(ip, IpAddr::V4(ip) if ip.is_broadcast())
}
