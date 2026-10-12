//! Bounded HTTP proxy authentication transport.
//! Bounded HTTP CONNECT authentication on one existing connection.
use crate::{
    http_connect::{self, HttpConnectError},
    sspi::{self, AuthScheme, Credentials, SspiClient, SspiError},
};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_HEADERS: usize = 65_536;
const MAX_BODY: usize = 1_048_576;
const MAX_ROUNDS: usize = 8;

pub struct AuthConfig<'a> {
    pub basic_credentials: Option<(&'a str, &'a str)>,
    /// None never acquires default current-user credentials implicitly.
    pub integrated_credentials: Option<Credentials<'a>>,
    pub preferred_scheme: AuthScheme,
    pub proxy_host: &'a str,
    pub user_agent: Option<&'a str>,
    /// Use a fresh context/Type1 when retrying a newly connected stream after407close.
    pub preemptive_scheme: Option<AuthScheme>,
}

impl<'a> AuthConfig<'a> {
    pub fn new(proxy_host: &'a str) -> Self {
        Self {
            basic_credentials: None,
            integrated_credentials: None,
            preferred_scheme: AuthScheme::Negotiate,
            proxy_host,
            user_agent: None,
            preemptive_scheme: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HttpAuthError {
    #[error(transparent)]
    Http(#[from] HttpConnectError),
    #[error(transparent)]
    Sspi(#[from] SspiError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("proxy authentication requires a new connection and context")]
    ReconnectRequired { scheme: Option<AuthScheme> },
    #[error("proxy did not offer an enabled authentication method")]
    NoSupportedAuthentication,
    #[error("HTTP proxy accepted an incomplete integrated authentication exchange")]
    IncompleteAuthentication,
    #[error("proxy authentication exceeded eight CONNECT requests")]
    TooManyRounds,
    #[error("proxy error response body exceeds 1 MiB")]
    BodyTooLarge,
    #[error("proxy authentication timed out")]
    Timeout,
    #[error("SSPI authentication worker could not complete")]
    WorkerFailed,
}

/// The timeout covers writes, headers, body draining and SSPI worker waits.
/// On any error the caller must discard the partially used connection. In
/// particular, ReconnectRequired requires restarting the chain and SSPI context.
pub async fn negotiate<S>(
    stream: &mut S,
    host: &str,
    port: u16,
    config: &AuthConfig<'_>,
    timeout: Duration,
) -> Result<(), HttpAuthError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    tokio::time::timeout(timeout, negotiate_inner(stream, host, port, config))
        .await
        .map_err(|_| HttpAuthError::Timeout)?
}

async fn negotiate_inner<S>(
    stream: &mut S,
    host: &str,
    port: u16,
    config: &AuthConfig<'_>,
) -> Result<(), HttpAuthError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let base = http_connect::request(host, port, config.basic_credentials)?;
    if base.len() > MAX_HEADERS {
        return Err(HttpConnectError::HeadersTooLarge.into());
    }
    if config
        .user_agent
        .is_some_and(|agent| agent.len() > 8192 || agent.bytes().any(|b| b < 32 || b == 127))
    {
        return Err(HttpConnectError::HeaderInjection.into());
    }
    let mut authorization = None;
    let mut selected = None;
    let mut context = None;
    let mut complete = false;
    if let Some(scheme) = config.preemptive_scheme {
        let credentials = config
            .integrated_credentials
            .as_ref()
            .ok_or(HttpAuthError::NoSupportedAuthentication)?;
        context = Some(new_context(scheme, config.proxy_host, credentials)?);
        let token = sspi_step(&mut context, None).await?;
        complete = token.complete;
        selected = Some(scheme);
        authorization = Some(token.authorization_value(scheme));
    }
    let mut header_bytes = 0;
    let mut body_bytes = 0;
    for round in 0..MAX_ROUNDS {
        let mut value = if authorization.is_some() {
            http_connect::request(host, port, None)?
        } else {
            base.clone()
        };
        value.truncate(value.len() - 2);
        if let Some(agent) = config.user_agent {
            value.push_str("User-Agent: ");
            value.push_str(agent);
            value.push_str("\r\n");
        }
        if let Some(auth) = authorization.as_deref() {
            value.push_str("Proxy-Authorization: ");
            value.push_str(auth);
            value.push_str("\r\n");
        }
        value.push_str("\r\n");
        if value.len() > MAX_HEADERS {
            return Err(HttpConnectError::HeadersTooLarge.into());
        }
        stream.write_all(value.as_bytes()).await?;
        stream.flush().await?;
        let response = read_response(stream, &mut header_bytes).await?;
        if (200..300).contains(&response.status) {
            // Negotiate can carry a final server token on the successful response.
            // Process it before exposing the stream, without consuming tunnel bytes.
            if !complete && let Some(scheme) = selected {
                let challenges = response.challenges()?;
                if let Some(challenge) = challenges.iter().find(|c| c.is_scheme(scheme))
                    && let Some(token) = challenge.decode_token()?
                {
                    let result = sspi_step(&mut context, Some(token)).await?;
                    if !result.complete || !result.bytes.is_empty() {
                        return Err(SspiError::InvalidState.into());
                    }
                    complete = result.complete;
                }
            }
            if context.is_some() && !complete {
                return Err(HttpAuthError::IncompleteAuthentication);
            }
            return Ok(());
        }
        if response.status != 407 {
            return Err(HttpConnectError::ConnectRejected(response.status).into());
        }
        let challenges = response.challenges()?;
        let offered = if config.integrated_credentials.is_some() {
            selected.or_else(|| enabled_scheme(config, &challenges))
        } else {
            None
        };
        drain_407(
            stream,
            &response,
            &mut header_bytes,
            &mut body_bytes,
            offered,
        )
        .await?;
        if round + 1 == MAX_ROUNDS {
            return Err(HttpAuthError::TooManyRounds);
        }
        let Some(credentials) = config.integrated_credentials.as_ref() else {
            return Err(HttpAuthError::NoSupportedAuthentication);
        };
        let scheme = if let Some(scheme) = selected {
            scheme
        } else {
            let fallback = match config.preferred_scheme {
                AuthScheme::Ntlm => AuthScheme::Negotiate,
                AuthScheme::Negotiate => AuthScheme::Ntlm,
            };
            [config.preferred_scheme, fallback]
                .into_iter()
                .find(|scheme| challenges.iter().any(|c| c.is_scheme(*scheme)))
                .ok_or(HttpAuthError::NoSupportedAuthentication)?
        };
        let challenge = challenges
            .iter()
            .find(|c| c.is_scheme(scheme))
            .ok_or(HttpAuthError::NoSupportedAuthentication)?;
        let server_token = if context.is_some() {
            challenge.decode_token()?
        } else {
            context = Some(new_context(scheme, config.proxy_host, credentials)?);
            selected = Some(scheme);
            None
        };
        let token = sspi_step(&mut context, server_token).await?;
        complete = token.complete;
        authorization = Some(token.authorization_value(scheme));
    }
    Err(HttpAuthError::TooManyRounds)
}

fn enabled_scheme(
    config: &AuthConfig<'_>,
    challenges: &[sspi::AuthChallenge],
) -> Option<AuthScheme> {
    let fallback = match config.preferred_scheme {
        AuthScheme::Ntlm => AuthScheme::Negotiate,
        AuthScheme::Negotiate => AuthScheme::Ntlm,
    };
    [config.preferred_scheme, fallback]
        .into_iter()
        .find(|scheme| {
            challenges
                .iter()
                .any(|challenge| challenge.is_scheme(*scheme))
        })
}

fn new_context(
    scheme: AuthScheme,
    proxy_host: &str,
    credentials: &Credentials<'_>,
) -> Result<SspiClient, SspiError> {
    let credentials = match credentials {
        Credentials::Default => Credentials::Default,
        Credentials::Explicit {
            username,
            password,
            domain,
        } => Credentials::Explicit {
            username,
            password,
            domain: *domain,
        },
    };
    SspiClient::new(scheme, &format!("HTTP/{proxy_host}"), credentials)
}

async fn sspi_step(
    context: &mut Option<SspiClient>,
    token: Option<Vec<u8>>,
) -> Result<sspi::AuthToken, HttpAuthError> {
    let mut client = context.take().ok_or(SspiError::InvalidState)?;
    let (client, result) = tokio::task::spawn_blocking(move || {
        let result = client.step(token.as_deref());
        (client, result)
    })
    .await
    .map_err(|_| HttpAuthError::WorkerFailed)?;
    *context = Some(client);
    Ok(result?)
}

struct Response {
    status: u16,
    http10: bool,
    fields: Vec<(String, String)>,
}

impl Response {
    fn values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.fields
            .iter()
            .filter(move |(field, _)| field == name)
            .map(|(_, value)| value.as_str())
    }
    fn has_token(&self, name: &str, token: &str) -> bool {
        self.values(name).any(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(token))
        })
    }
    fn challenges(&self) -> Result<Vec<sspi::AuthChallenge>, SspiError> {
        let mut result = Vec::new();
        for value in self.values("proxy-authenticate") {
            result.extend(sspi::parse_challenges(value)?);
        }
        if result.len() > 64 {
            return Err(SspiError::MalformedChallenge);
        }
        Ok(result)
    }
}

async fn read_response<S: AsyncRead + Unpin>(
    stream: &mut S,
    total: &mut usize,
) -> Result<Response, HttpAuthError> {
    for _ in 0..32 {
        let mut bytes = Vec::new();
        loop {
            if *total >= MAX_HEADERS {
                return Err(HttpConnectError::HeadersTooLarge.into());
            }
            bytes.push(stream.read_u8().await?);
            *total += 1;
            if bytes.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let status = http_connect::parse_response(&bytes)?;
        if (100..200).contains(&status) && status != 101 {
            continue;
        }
        let lines: Vec<_> = bytes.split(|b| *b == b'\n').collect();
        let mut fields = Vec::new();
        for line in lines.iter().skip(1).take(lines.len().saturating_sub(3)) {
            let line = &line[..line.len() - 1];
            let colon = line
                .iter()
                .position(|b| *b == b':')
                .ok_or(HttpConnectError::MalformedResponse)?;
            fields.push((
                String::from_utf8_lossy(&line[..colon]).to_ascii_lowercase(),
                String::from_utf8_lossy(&line[colon + 1..])
                    .trim_matches([' ', '\t'])
                    .to_owned(),
            ));
        }
        return Ok(Response {
            status,
            http10: bytes.starts_with(b"HTTP/1.0 "),
            fields,
        });
    }
    Err(HttpConnectError::TooManyInformationalResponses.into())
}

async fn drain_407<S: AsyncRead + Unpin>(
    stream: &mut S,
    response: &Response,
    headers: &mut usize,
    bodies: &mut usize,
    scheme: Option<AuthScheme>,
) -> Result<(), HttpAuthError> {
    if response.has_token("connection", "close")
        || response.has_token("proxy-connection", "close")
        || (response.http10
            && !response.has_token("connection", "keep-alive")
            && !response.has_token("proxy-connection", "keep-alive"))
    {
        return Err(HttpAuthError::ReconnectRequired { scheme });
    }
    let lengths: Vec<_> = response.values("content-length").collect();
    let encodings: Vec<_> = response.values("transfer-encoding").collect();
    if lengths.len() > 1 || encodings.len() > 1 || (!lengths.is_empty() && !encodings.is_empty()) {
        return Err(HttpConnectError::MalformedResponse.into());
    }
    if let Some(length) = lengths.first() {
        if length.is_empty() || !length.bytes().all(|b| b.is_ascii_digit()) {
            return Err(HttpConnectError::MalformedResponse.into());
        }
        let length = length
            .parse::<usize>()
            .map_err(|_| HttpAuthError::BodyTooLarge)?;
        drain_exact(stream, length, bodies).await?;
    } else if let Some(encoding) = encodings.first() {
        if !encoding.eq_ignore_ascii_case("chunked") {
            return Err(HttpConnectError::MalformedResponse.into());
        }
        loop {
            let line = read_line(stream, headers).await?;
            let size = line.split(|b| *b == b';').next().unwrap_or_default();
            if size.is_empty() || !size.iter().all(u8::is_ascii_hexdigit) {
                return Err(HttpConnectError::MalformedResponse.into());
            }
            let size = usize::from_str_radix(
                std::str::from_utf8(size).map_err(|_| HttpConnectError::MalformedResponse)?,
                16,
            )
            .map_err(|_| HttpAuthError::BodyTooLarge)?;
            if size == 0 {
                break;
            }
            drain_exact(stream, size, bodies).await?;
            let mut ending = [0; 2];
            stream.read_exact(&mut ending).await?;
            if ending != *b"\r\n" {
                return Err(HttpConnectError::MalformedResponse.into());
            }
        }
        loop {
            let trailer = read_line(stream, headers).await?;
            if trailer.is_empty() {
                break;
            }
            let colon = trailer
                .iter()
                .position(|b| *b == b':')
                .ok_or(HttpConnectError::MalformedResponse)?;
            if colon == 0
                || !trailer[..colon]
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(b))
            {
                return Err(HttpConnectError::MalformedResponse.into());
            }
            if trailer[..colon].eq_ignore_ascii_case(b"content-length")
                || trailer[..colon].eq_ignore_ascii_case(b"transfer-encoding")
            {
                return Err(HttpConnectError::MalformedResponse.into());
            }
        }
    } else {
        return Err(HttpAuthError::ReconnectRequired { scheme });
    }
    Ok(())
}

async fn drain_exact<S: AsyncRead + Unpin>(
    stream: &mut S,
    length: usize,
    total: &mut usize,
) -> Result<(), HttpAuthError> {
    if length > MAX_BODY.saturating_sub(*total) {
        return Err(HttpAuthError::BodyTooLarge);
    }
    *total += length;
    let mut remaining = length;
    let mut buffer = [0; 4096];
    while remaining > 0 {
        let count = remaining.min(buffer.len());
        stream.read_exact(&mut buffer[..count]).await?;
        remaining -= count;
    }
    Ok(())
}

async fn read_line<S: AsyncRead + Unpin>(
    stream: &mut S,
    total: &mut usize,
) -> Result<Vec<u8>, HttpAuthError> {
    let mut line = Vec::new();
    loop {
        if *total >= MAX_HEADERS || line.len() >= 8192 {
            return Err(HttpConnectError::HeadersTooLarge.into());
        }
        line.push(stream.read_u8().await?);
        *total += 1;
        if line.ends_with(b"\r\n") {
            line.truncate(line.len() - 2);
            if line.iter().any(|b| (*b < 32 && *b != b'\t') || *b == 127) {
                return Err(HttpConnectError::MalformedResponse.into());
            }
            return Ok(line);
        }
    }
}
