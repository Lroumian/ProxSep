//! Current-user or explicitly supplied SSPI proxy authentication.
//! HTTP connection reuse, 407 handling and response draining belong to the
//! transport layer. This module only parses challenges and produces opaque tokens.
use base64::{Engine as _, engine::general_purpose::STANDARD};

const MAX_HEADER: usize = 65_536;
#[cfg(windows)]
const MAX_TOKEN: usize = 1_048_576;

#[derive(Debug, thiserror::Error)]
pub enum SspiError {
    #[error("authentication challenge exceeds 64 KiB")]
    HeaderTooLarge,
    #[error("malformed HTTP authentication challenge")]
    MalformedChallenge,
    #[error("invalid or oversized authentication token")]
    InvalidToken,
    #[error("invalid SSPI target or credentials")]
    InvalidInput,
    #[error("SSPI authentication exchange cannot continue in its current state")]
    InvalidState,
    #[error("SSPI package reported an invalid token size")]
    PackageBounds,
    #[error("SSPI {operation} failed with status {status:#010x}")]
    Status {
        operation: &'static str,
        status: u32,
    },
    #[error("Windows SSPI is unavailable on this platform")]
    UnsupportedPlatform,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthScheme {
    Ntlm,
    Negotiate,
}

impl AuthScheme {
    pub fn header_name(self) -> &'static str {
        match self {
            Self::Ntlm => "NTLM",
            Self::Negotiate => "Negotiate",
        }
    }
}

/// Borrowed credentials deliberately have no Debug implementation.
pub enum Credentials<'a> {
    Default,
    Explicit {
        username: &'a str,
        password: &'a str,
        domain: Option<&'a str>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthChallenge {
    pub scheme: String,
    pub token68: Option<String>,
    pub parameters: Vec<(String, String)>,
}

impl AuthChallenge {
    pub fn is_scheme(&self, scheme: AuthScheme) -> bool {
        self.scheme.eq_ignore_ascii_case(scheme.header_name())
    }
    pub fn decode_token(&self) -> Result<Option<Vec<u8>>, SspiError> {
        if !self.parameters.is_empty() {
            return Err(SspiError::InvalidToken);
        }
        self.token68
            .as_ref()
            .map(|token| {
                if token.len() > MAX_HEADER {
                    return Err(SspiError::InvalidToken);
                }
                STANDARD.decode(token).map_err(|_| SspiError::InvalidToken)
            })
            .transpose()
    }
}

fn tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn token68(value: &str) -> bool {
    let base = value.trim_end_matches('=');
    !base.is_empty()
        && base
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-._~+/".contains(&b))
}

fn parse_parameter(value: &str) -> Result<(String, String), SspiError> {
    let bytes = value.as_bytes();
    let end = bytes.iter().position(|b| !tchar(*b)).unwrap_or(bytes.len());
    if end == 0 {
        return Err(SspiError::MalformedChallenge);
    }
    let name = value[..end].to_owned();
    let rest = value[end..].trim_start_matches([' ', '\t']);
    let rest = rest
        .strip_prefix('=')
        .ok_or(SspiError::MalformedChallenge)?
        .trim_start_matches([' ', '\t']);
    if let Some(quoted) = rest.strip_prefix('"') {
        let mut decoded = Vec::new();
        let mut escape = false;
        for (index, byte) in quoted.bytes().enumerate() {
            if escape {
                decoded.push(byte);
                escape = false;
            } else if byte == b'\\' {
                escape = true;
            } else if byte == b'"' {
                if !quoted[index + 1..].trim_matches([' ', '\t']).is_empty() {
                    return Err(SspiError::MalformedChallenge);
                }
                return Ok((
                    name,
                    String::from_utf8(decoded).map_err(|_| SspiError::MalformedChallenge)?,
                ));
            } else {
                decoded.push(byte);
            }
        }
        Err(SspiError::MalformedChallenge)
    } else {
        if rest.is_empty() || !rest.bytes().all(tchar) {
            return Err(SspiError::MalformedChallenge);
        }
        Ok((name, rest.to_owned()))
    }
}

/// RFC 9110 challenge lists contain commas in both parameter lists and quoted
/// strings. A parameter continues the previous challenge; a scheme starts a new
/// one. Scheme and parameter names are case-insensitive when compared.
pub fn parse_challenges(value: &str) -> Result<Vec<AuthChallenge>, SspiError> {
    if value.len() > MAX_HEADER {
        return Err(SspiError::HeaderTooLarge);
    }
    if value.bytes().any(|b| (b < 32 && b != b'\t') || b == 127) {
        return Err(SspiError::MalformedChallenge);
    }
    let mut segments = Vec::new();
    let (mut quoted, mut escaped, mut start) = (false, false, 0);
    for (index, byte) in value.bytes().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        if quoted && byte == b'\\' {
            escaped = true;
        } else if byte == b'"' {
            quoted = !quoted;
        } else if byte == b',' && !quoted {
            segments.push(&value[start..index]);
            start = index + 1;
        }
    }
    if quoted || escaped {
        return Err(SspiError::MalformedChallenge);
    }
    segments.push(&value[start..]);
    let mut challenges: Vec<AuthChallenge> = Vec::new();
    for segment in segments {
        let segment = segment.trim_matches([' ', '\t']);
        if segment.is_empty() {
            continue;
        }
        let end = segment
            .bytes()
            .position(|b| !tchar(b))
            .unwrap_or(segment.len());
        if end == 0 {
            return Err(SspiError::MalformedChallenge);
        }
        let rest = segment[end..].trim_start_matches([' ', '\t']);
        if rest.starts_with('=') {
            let challenge = challenges.last_mut().ok_or(SspiError::MalformedChallenge)?;
            if challenge.token68.is_some() || challenge.parameters.is_empty() {
                return Err(SspiError::MalformedChallenge);
            }
            let parameter = parse_parameter(segment)?;
            if challenge.parameters.len() >= 64
                || challenge
                    .parameters
                    .iter()
                    .any(|(name, _)| name.eq_ignore_ascii_case(&parameter.0))
            {
                return Err(SspiError::MalformedChallenge);
            }
            challenge.parameters.push(parameter);
        } else {
            if challenges.len() >= 64 {
                return Err(SspiError::MalformedChallenge);
            }
            if !rest.is_empty() && !segment[end..].starts_with(' ') {
                return Err(SspiError::MalformedChallenge);
            }
            let mut challenge = AuthChallenge {
                scheme: segment[..end].to_owned(),
                token68: None,
                parameters: Vec::new(),
            };
            if !rest.is_empty() {
                if token68(rest) {
                    challenge.token68 = Some(rest.to_owned());
                } else {
                    challenge.parameters.push(parse_parameter(rest)?);
                }
            }
            challenges.push(challenge);
        }
    }
    Ok(challenges)
}

pub struct AuthToken {
    pub bytes: Vec<u8>,
    pub complete: bool,
}

impl std::fmt::Debug for AuthToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthToken")
            .field("length", &self.bytes.len())
            .field("complete", &self.complete)
            .finish()
    }
}

impl AuthToken {
    pub fn authorization_value(&self, scheme: AuthScheme) -> String {
        format!("{} {}", scheme.header_name(), STANDARD.encode(&self.bytes))
    }
}

pub struct SspiClient {
    #[cfg(windows)]
    inner: windows::Client,
}

impl SspiClient {
    /// `target_spn` must be the proxy service principal, e.g. HTTP/proxy.example.
    /// Recreate the context if HTTP transport reconnects. Contexts must not be
    /// reused concurrently; the mutable step API enforces that restriction.
    pub fn new(
        scheme: AuthScheme,
        target_spn: &str,
        credentials: Credentials<'_>,
    ) -> Result<Self, SspiError> {
        validate_inputs(scheme, target_spn, &credentials)?;
        #[cfg(windows)]
        {
            Ok(Self {
                inner: windows::Client::new(scheme, target_spn, credentials)?,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = (scheme, target_spn, credentials);
            Err(SspiError::UnsupportedPlatform)
        }
    }

    pub fn step(&mut self, server_token: Option<&[u8]>) -> Result<AuthToken, SspiError> {
        #[cfg(windows)]
        {
            self.inner.step(server_token)
        }
        #[cfg(not(windows))]
        {
            let _ = server_token;
            Err(SspiError::UnsupportedPlatform)
        }
    }
}

fn validate_inputs(
    scheme: AuthScheme,
    target: &str,
    credentials: &Credentials<'_>,
) -> Result<(), SspiError> {
    if target.is_empty()
        || !target.contains('/')
        || target.contains('\0')
        || target.encode_utf16().count() > 1024
    {
        return Err(SspiError::InvalidInput);
    }
    if let Credentials::Explicit {
        username,
        password,
        domain,
    } = credentials
    {
        let (username, domain) = split_username(username, *domain)?;
        let domain_limit = if scheme == AuthScheme::Ntlm { 15 } else { 255 };
        if username.is_empty()
            || username.contains('\0')
            || password.contains('\0')
            || domain.contains('\0')
            || username.encode_utf16().count() > 256
            || password.encode_utf16().count() > 256
            || domain.encode_utf16().count() > domain_limit
        {
            return Err(SspiError::InvalidInput);
        }
    }
    Ok(())
}

fn split_username<'a>(
    username: &'a str,
    domain: Option<&'a str>,
) -> Result<(&'a str, &'a str), SspiError> {
    if let Some((embedded, user)) = username.split_once('\\') {
        if domain.is_some() || embedded.is_empty() || user.contains('\\') {
            return Err(SspiError::InvalidInput);
        }
        Ok((user, embedded))
    } else {
        Ok((username, domain.unwrap_or("")))
    }
}

#[cfg(windows)]
mod windows {
    use super::{AuthScheme, AuthToken, Credentials, MAX_TOKEN, SspiError, split_username};
    use std::{ffi::c_void, ptr};

    #[repr(C)]
    struct SecHandle {
        lower: usize,
        upper: usize,
    }
    impl SecHandle {
        fn invalid() -> Self {
            Self {
                lower: usize::MAX,
                upper: usize::MAX,
            }
        }
        fn valid(&self) -> bool {
            self.lower != usize::MAX || self.upper != usize::MAX
        }
    }
    #[repr(C)]
    struct TimeStamp {
        low: u32,
        high: i32,
    }
    #[repr(C)]
    struct SecBuffer {
        length: u32,
        kind: u32,
        data: *mut c_void,
    }
    #[repr(C)]
    struct SecBufferDesc {
        version: u32,
        count: u32,
        buffers: *mut SecBuffer,
    }
    #[repr(C)]
    struct SecPkgInfo {
        capabilities: u32,
        version: u16,
        rpc_id: u16,
        max_token: u32,
        name: *mut u16,
        comment: *mut u16,
    }
    #[repr(C)]
    struct AuthIdentity {
        user: *mut u16,
        user_length: u32,
        domain: *mut u16,
        domain_length: u32,
        password: *mut u16,
        password_length: u32,
        flags: u32,
    }

    #[link(name = "secur32")]
    unsafe extern "system" {
        fn QuerySecurityPackageInfoW(package: *mut u16, info: *mut *mut SecPkgInfo) -> i32;
        fn AcquireCredentialsHandleW(
            principal: *mut u16,
            package: *mut u16,
            usage: u32,
            logon: *mut c_void,
            auth: *mut c_void,
            key_fn: *mut c_void,
            key_arg: *mut c_void,
            credential: *mut SecHandle,
            expiry: *mut TimeStamp,
        ) -> i32;
        fn InitializeSecurityContextW(
            credential: *mut SecHandle,
            context: *mut SecHandle,
            target: *mut u16,
            requirements: u32,
            reserved1: u32,
            representation: u32,
            input: *mut SecBufferDesc,
            reserved2: u32,
            new_context: *mut SecHandle,
            output: *mut SecBufferDesc,
            attributes: *mut u32,
            expiry: *mut TimeStamp,
        ) -> i32;
        fn CompleteAuthToken(context: *mut SecHandle, token: *mut SecBufferDesc) -> i32;
        fn DeleteSecurityContext(context: *mut SecHandle) -> i32;
        fn FreeCredentialsHandle(credential: *mut SecHandle) -> i32;
        fn FreeContextBuffer(buffer: *mut c_void) -> i32;
    }

    // All pointers below refer to explicitly sized, live allocations. SSPI
    // output allocations are always freed by FreeContextBuffer, not Rust.
    struct PackageBuffer(*mut SecPkgInfo);
    impl Drop for PackageBuffer {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe {
                    FreeContextBuffer(self.0.cast());
                }
            }
        }
    }
    struct OutputBuffer(SecBuffer);
    impl Drop for OutputBuffer {
        fn drop(&mut self) {
            if !self.0.data.is_null() {
                unsafe {
                    FreeContextBuffer(self.0.data);
                }
            }
        }
    }

    struct WideSecret(Vec<u16>);
    impl Drop for WideSecret {
        fn drop(&mut self) {
            for unit in &mut self.0 {
                unsafe {
                    ptr::write_volatile(unit, 0);
                }
            }
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
        }
    }
    struct OwnedIdentity {
        user: Vec<u16>,
        domain: Vec<u16>,
        password: WideSecret,
    }
    impl OwnedIdentity {
        fn raw(&mut self) -> AuthIdentity {
            AuthIdentity {
                user: self.user.as_mut_ptr(),
                user_length: self.user.len() as u32,
                domain: self.domain.as_mut_ptr(),
                domain_length: self.domain.len() as u32,
                password: self.password.0.as_mut_ptr(),
                password_length: self.password.0.len() as u32,
                flags: 2,
            }
        }
    }
    struct Credential {
        handle: SecHandle,
        _identity: Option<OwnedIdentity>,
    }
    impl Drop for Credential {
        fn drop(&mut self) {
            if self.handle.valid() {
                unsafe {
                    FreeCredentialsHandle(&mut self.handle);
                }
            }
        }
    }
    struct Context {
        handle: SecHandle,
    }
    impl Drop for Context {
        fn drop(&mut self) {
            if self.handle.valid() {
                unsafe {
                    DeleteSecurityContext(&mut self.handle);
                }
            }
        }
    }

    pub(super) struct Client {
        // Field order makes context cleanup happen before credential cleanup.
        context: Context,
        credential: Credential,
        target: Vec<u16>,
        max_token: usize,
        started: bool,
        finished: bool,
        failed: bool,
    }

    fn status(operation: &'static str, value: i32) -> SspiError {
        SspiError::Status {
            operation,
            status: value as u32,
        }
    }
    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain([0]).collect()
    }

    impl Client {
        pub(super) fn new(
            scheme: AuthScheme,
            target: &str,
            credentials: Credentials<'_>,
        ) -> Result<Self, SspiError> {
            let mut package = wide(scheme.header_name());
            let mut info = ptr::null_mut();
            let result = unsafe { QuerySecurityPackageInfoW(package.as_mut_ptr(), &mut info) };
            let package_info = PackageBuffer(info);
            if result != 0 {
                return Err(status("QuerySecurityPackageInfoW", result));
            }
            if package_info.0.is_null() {
                return Err(SspiError::PackageBounds);
            }
            let max_token = unsafe { (*package_info.0).max_token as usize };
            if max_token == 0 || max_token > MAX_TOKEN {
                return Err(SspiError::PackageBounds);
            }
            let mut identity = match credentials {
                Credentials::Default => None,
                Credentials::Explicit {
                    username,
                    password,
                    domain,
                } => {
                    let (username, domain) = split_username(username, domain)?;
                    Some(OwnedIdentity {
                        user: username.encode_utf16().collect(),
                        domain: domain.encode_utf16().collect(),
                        password: WideSecret(password.encode_utf16().collect()),
                    })
                }
            };
            let mut raw = identity.as_mut().map(OwnedIdentity::raw);
            let auth = raw
                .as_mut()
                .map_or(ptr::null_mut(), |raw| (raw as *mut AuthIdentity).cast());
            let mut handle = SecHandle::invalid();
            let mut expiry = TimeStamp { low: 0, high: 0 };
            let result = unsafe {
                AcquireCredentialsHandleW(
                    ptr::null_mut(),
                    package.as_mut_ptr(),
                    2,
                    ptr::null_mut(),
                    auth,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut handle,
                    &mut expiry,
                )
            };
            if result != 0 {
                return Err(status("AcquireCredentialsHandleW", result));
            }
            Ok(Self {
                context: Context {
                    handle: SecHandle::invalid(),
                },
                credential: Credential {
                    handle,
                    _identity: identity,
                },
                target: wide(target),
                max_token,
                started: false,
                finished: false,
                failed: false,
            })
        }

        pub(super) fn step(&mut self, server_token: Option<&[u8]>) -> Result<AuthToken, SspiError> {
            if self.failed
                || self.finished
                || (self.started && server_token.is_none())
                || (!self.started && server_token.is_some())
            {
                return Err(SspiError::InvalidState);
            }
            if server_token.is_some_and(|token| token.is_empty() || token.len() > self.max_token) {
                return Err(SspiError::InvalidToken);
            }
            let mut input_bytes = server_token.map(<[u8]>::to_vec);
            let mut input = SecBuffer {
                length: input_bytes.as_ref().map_or(0, |b| b.len() as u32),
                kind: 2,
                data: input_bytes
                    .as_mut()
                    .map_or(ptr::null_mut(), |b| b.as_mut_ptr().cast()),
            };
            let mut input_desc = SecBufferDesc {
                version: 0,
                count: 1,
                buffers: &mut input,
            };
            let mut output = OutputBuffer(SecBuffer {
                length: 0,
                kind: 2,
                data: ptr::null_mut(),
            });
            let mut output_desc = SecBufferDesc {
                version: 0,
                count: 1,
                buffers: &mut output.0,
            };
            let context = if self.started {
                &mut self.context.handle as *mut SecHandle
            } else {
                ptr::null_mut()
            };
            let input = if input_bytes.is_some() {
                &mut input_desc as *mut SecBufferDesc
            } else {
                ptr::null_mut()
            };
            let mut attributes = 0;
            let result = unsafe {
                InitializeSecurityContextW(
                    &mut self.credential.handle,
                    context,
                    self.target.as_mut_ptr(),
                    0x100 | 0x800,
                    0,
                    0x10,
                    input,
                    0,
                    &mut self.context.handle,
                    &mut output_desc,
                    &mut attributes,
                    ptr::null_mut(),
                )
            };
            match result as u32 {
                0 | 0x0009_0312 | 0x0009_0313 | 0x0009_0314 => {}
                _ => {
                    self.failed = true;
                    return Err(status("InitializeSecurityContextW", result));
                }
            }
            self.started = true;
            if matches!(result as u32, 0x0009_0313 | 0x0009_0314) {
                let completion =
                    unsafe { CompleteAuthToken(&mut self.context.handle, &mut output_desc) };
                if completion != 0 {
                    self.failed = true;
                    return Err(status("CompleteAuthToken", completion));
                }
            }
            let length = output.0.length as usize;
            if length > self.max_token || (length > 0 && output.0.data.is_null()) {
                self.failed = true;
                return Err(SspiError::PackageBounds);
            }
            let bytes = if length == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(output.0.data.cast::<u8>(), length) }.to_vec()
            };
            let complete = matches!(result as u32, 0 | 0x0009_0313);
            self.finished = complete;
            Ok(AuthToken { bytes, complete })
        }
    }
}
