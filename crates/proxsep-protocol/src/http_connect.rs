use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::{net::Ipv6Addr, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, thiserror::Error)]
pub enum HttpConnectError {
    #[error("host or credentials contain a forbidden line break")]
    HeaderInjection,
    #[error("invalid HTTP CONNECT destination authority")]
    InvalidAuthority,
    #[error("Basic authentication username contains a colon")]
    InvalidCredentials,
    #[error("proxy response headers exceeded 64 KiB")]
    HeadersTooLarge,
    #[error("malformed HTTP proxy response")]
    MalformedResponse,
    #[error("HTTP proxy rejected CONNECT with status {0}")]
    ConnectRejected(u16),
    #[error("too many informational HTTP responses")]
    TooManyInformationalResponses,
    #[error("proxy handshake timed out")]
    Timeout,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub fn request(
    host: &str,
    port: u16,
    credentials: Option<(&str, &str)>,
) -> Result<String, HttpConnectError> {
    if [
        host,
        credentials.map(|value| value.0).unwrap_or(""),
        credentials.map(|value| value.1).unwrap_or(""),
    ]
    .iter()
    .any(|value| value.contains(['\r', '\n']))
    {
        return Err(HttpConnectError::HeaderInjection);
    }
    if credentials.is_some_and(|(username, _)| username.contains(':')) {
        return Err(HttpConnectError::InvalidCredentials);
    }
    let ipv6 = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let authority = if ipv6.parse::<Ipv6Addr>().is_ok() {
        format!("[{ipv6}]:{port}")
    } else {
        if host.is_empty()
            || !host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_'))
        {
            return Err(HttpConnectError::InvalidAuthority);
        }
        format!("{host}:{port}")
    };
    let mut value = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n"
    );
    if let Some((username, password)) = credentials {
        value.push_str("Proxy-Authorization: Basic ");
        value.push_str(&STANDARD.encode(format!("{username}:{password}")));
        value.push_str("\r\n");
    }
    value.push_str("\r\n");
    Ok(value)
}

pub async fn negotiate<S>(
    stream: &mut S,
    host: &str,
    port: u16,
    credentials: Option<(&str, &str)>,
) -> Result<(), HttpConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream
        .write_all(request(host, port, credentials)?.as_bytes())
        .await?;
    stream.flush().await?;
    let mut total_bytes = 0;
    for _ in 0..32 {
        let mut headers = Vec::with_capacity(512);
        loop {
            if total_bytes >= 65_536 {
                return Err(HttpConnectError::HeadersTooLarge);
            }
            // Read exactly through the header terminator so bytes delivered in
            // the same packet as the response remain available to the tunnel.
            headers.push(stream.read_u8().await?);
            total_bytes += 1;
            if headers.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let status = parse_response(&headers)?;
        if (100..200).contains(&status) && status != 101 {
            continue;
        }
        if !(200..300).contains(&status) {
            return Err(HttpConnectError::ConnectRejected(status));
        }
        return Ok(());
    }
    Err(HttpConnectError::TooManyInformationalResponses)
}

pub(crate) fn parse_response(headers: &[u8]) -> Result<u16, HttpConnectError> {
    let lines: Vec<_> = headers.split(|b| *b == b'\n').collect();
    let status_line = lines.first().ok_or(HttpConnectError::MalformedResponse)?;
    let line = status_line
        .strip_suffix(b"\r")
        .ok_or(HttpConnectError::MalformedResponse)?;
    if line.len() < 13
        || !(line.starts_with(b"HTTP/1.1 ") || line.starts_with(b"HTTP/1.0 "))
        || line[12] != b' '
        || !line[9..12].iter().all(u8::is_ascii_digit)
        || line[13..]
            .iter()
            .any(|b| (*b < 32 && *b != b'\t') || *b == 127)
    {
        return Err(HttpConnectError::MalformedResponse);
    }
    let status = u16::from(line[9] - b'0') * 100
        + u16::from(line[10] - b'0') * 10
        + u16::from(line[11] - b'0');
    if !(100..600).contains(&status) {
        return Err(HttpConnectError::MalformedResponse);
    }
    for raw_line in lines.iter().skip(1).take(lines.len().saturating_sub(3)) {
        let line = raw_line
            .strip_suffix(b"\r")
            .ok_or(HttpConnectError::MalformedResponse)?;
        let colon = line
            .iter()
            .position(|b| *b == b':')
            .ok_or(HttpConnectError::MalformedResponse)?;
        if colon == 0
            || !line[..colon]
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(b))
            || line[colon + 1..]
                .iter()
                .any(|b| (*b < 32 && *b != b'\t') || *b == 127)
        {
            return Err(HttpConnectError::MalformedResponse);
        }
    }
    Ok(status)
}

/// Discard the partially negotiated stream if the deadline expires.
pub async fn negotiate_with_timeout<S>(
    stream: &mut S,
    host: &str,
    port: u16,
    credentials: Option<(&str, &str)>,
    timeout: Duration,
) -> Result<(), HttpConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tokio::time::timeout(timeout, negotiate(stream, host, port, credentials))
        .await
        .map_err(|_| HttpConnectError::Timeout)?
}
