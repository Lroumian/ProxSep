//! SOCKS4 and SOCKS4a client CONNECT requests.
use std::{
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, thiserror::Error)]
pub enum Socks4Error {
    #[error("invalid SOCKS4 host or user ID")]
    InvalidInput,
    #[error("SOCKS4 does not support IPv6 destinations")]
    Ipv6Unsupported,
    #[error("malformed SOCKS4 reply")]
    MalformedResponse,
    #[error("SOCKS4 proxy rejected CONNECT with status {0}")]
    ConnectRejected(u8),
    #[error("proxy handshake timed out")]
    Timeout,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// IPv4 literals use SOCKS4, hostnames use SOCKS4a. For local resolution,
/// callers should resolve first and pass the resulting IPv4 literal.
pub fn connect_request(host: &str, port: u16, user_id: &str) -> Result<Vec<u8>, Socks4Error> {
    if host.is_empty()
        || host.len() > 255
        || host.chars().any(|c| c.is_control() || c.is_whitespace())
        || user_id.contains('\0')
        || user_id.len() > 255
    {
        return Err(Socks4Error::InvalidInput);
    }
    let ip = match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => Some(ip),
        Ok(IpAddr::V6(_)) => return Err(Socks4Error::Ipv6Unsupported),
        Err(_) => None,
    };
    if ip.is_some_and(|ip| ip.octets()[..3] == [0, 0, 0] && ip.octets()[3] != 0) {
        return Err(Socks4Error::InvalidInput);
    }
    let mut request = vec![4, 1];
    request.extend(port.to_be_bytes());
    request.extend(ip.unwrap_or(Ipv4Addr::new(0, 0, 0, 1)).octets());
    request.extend(user_id.as_bytes());
    request.push(0);
    if ip.is_none() {
        request.extend(host.as_bytes());
        request.push(0);
    }
    Ok(request)
}

pub async fn negotiate<S>(
    stream: &mut S,
    host: &str,
    port: u16,
    user_id: &str,
) -> Result<(), Socks4Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream
        .write_all(&connect_request(host, port, user_id)?)
        .await?;
    stream.flush().await?;
    let mut response = [0; 8];
    stream.read_exact(&mut response).await?;
    if response[0] != 0 {
        return Err(Socks4Error::MalformedResponse);
    }
    if response[1] != 90 {
        return Err(Socks4Error::ConnectRejected(response[1]));
    }
    Ok(())
}

/// Discard the stream after an error or timeout; negotiation cannot be resumed.
pub async fn negotiate_with_timeout<S>(
    stream: &mut S,
    host: &str,
    port: u16,
    user_id: &str,
    timeout: Duration,
) -> Result<(), Socks4Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tokio::time::timeout(timeout, negotiate(stream, host, port, user_id))
        .await
        .map_err(|_| Socks4Error::Timeout)?
}
