use proxsep_protocol::sspi::{AuthScheme, Credentials, SspiClient, SspiError, parse_challenges};

#[test]
fn parses_challenge_lists_without_splitting_quoted_commas() {
    let challenges = parse_challenges(
        "Basic realm=\"proxy, office\", charset=\"UTF-8\", Negotiate, NTLM TlRMTVNTUAABAAAA",
    )
    .unwrap();
    assert_eq!(challenges.len(), 3);
    assert_eq!(challenges[0].scheme, "Basic");
    assert_eq!(
        challenges[0].parameters,
        vec![
            ("realm".into(), "proxy, office".into()),
            ("charset".into(), "UTF-8".into())
        ]
    );
    assert_eq!(challenges[1].scheme, "Negotiate");
    assert_eq!(challenges[1].token68, None);
    assert_eq!(
        challenges[2].decode_token().unwrap().unwrap(),
        b"NTLMSSP\0\x01\0\0\0"
    );
}

#[test]
fn challenge_quoted_pairs_and_padding_are_parsed() {
    let challenges =
        parse_challenges("Digest realm=\"a\\\"b\\\\c\", nonce=\"x,y\", algorithm=MD5, NTLM YQ==")
            .unwrap();
    assert_eq!(challenges[0].parameters[0].1, "a\"b\\c");
    assert_eq!(challenges[1].decode_token().unwrap().unwrap(), b"a");
    assert_eq!(parse_challenges(",,NTLM,,Negotiate,").unwrap().len(), 2);
}

#[test]
fn malformed_challenges_and_duplicate_params_are_rejected() {
    for value in [
        "Basic realm=\"open",
        "Basic realm=\"x\" trailing",
        "realm=\"x\"",
        "NTLM YQ==, realm=\"x\"",
        "Basic realm=\"x\", Realm=\"y\"",
        "NTLM\r\nInjected: value",
        "Basic =value",
        "NTLM YQ==junk",
    ] {
        assert!(parse_challenges(value).is_err(), "{value:?}");
    }
    assert!(parse_challenges(&"x".repeat(65_537)).is_err());
    let bad = parse_challenges("NTLM ____").unwrap();
    assert!(matches!(
        bad[0].decode_token(),
        Err(SspiError::InvalidToken)
    ));
    // A trailing '=' is legal token68 grammar, not necessarily an empty param.
    assert_eq!(
        parse_challenges("Basic realm=").unwrap()[0]
            .token68
            .as_deref(),
        Some("realm=")
    );
    let parameters = parse_challenges("NTLM bad=padding").unwrap();
    assert!(matches!(
        parameters[0].decode_token(),
        Err(SspiError::InvalidToken)
    ));
}

#[test]
fn scheme_and_input_validation_are_explicit() {
    assert_eq!(AuthScheme::Ntlm.header_name(), "NTLM");
    assert_eq!(AuthScheme::Negotiate.header_name(), "Negotiate");
    assert!(
        SspiClient::new(
            AuthScheme::Ntlm,
            "HTTP/localhost\0extra",
            Credentials::Default
        )
        .is_err()
    );
    assert!(SspiClient::new(AuthScheme::Ntlm, "", Credentials::Default).is_err());
    assert!(
        SspiClient::new(
            AuthScheme::Ntlm,
            "HTTP/localhost",
            Credentials::Explicit {
                username: "u\0x",
                password: "p",
                domain: None
            }
        )
        .is_err()
    );
}

#[cfg(windows)]
#[test]
fn windows_sspi_generates_local_ntlm_type1_without_network() {
    let mut client =
        SspiClient::new(AuthScheme::Ntlm, "HTTP/localhost", Credentials::Default).unwrap();
    let token = client.step(None).unwrap();
    // Inspect only protocol prefix/type, never print the authentication token.
    assert!(token.bytes.len() >= 12);
    assert_eq!(&token.bytes[..8], b"NTLMSSP\0");
    assert_eq!(
        u32::from_le_bytes(token.bytes[8..12].try_into().unwrap()),
        1
    );
    assert!(!token.complete);
    assert!(
        token
            .authorization_value(AuthScheme::Ntlm)
            .starts_with("NTLM ")
    );
    assert!(client.step(Some(&[])).is_err());
}

#[cfg(windows)]
#[test]
fn explicit_credentials_can_generate_ntlm_type1_locally() {
    let mut client = SspiClient::new(
        AuthScheme::Ntlm,
        "HTTP/localhost",
        Credentials::Explicit {
            username: "protocol-test",
            password: "not-a-real-secret",
            domain: Some("."),
        },
    )
    .unwrap();
    let token = client.step(None).unwrap();
    assert_eq!(&token.bytes[..8], b"NTLMSSP\0");
    assert!(!token.complete);
}

#[cfg(windows)]
#[test]
fn malformed_server_token_is_an_sspi_error_and_context_cannot_resume() {
    let mut client =
        SspiClient::new(AuthScheme::Ntlm, "HTTP/localhost", Credentials::Default).unwrap();
    client.step(None).unwrap();
    assert!(matches!(
        client.step(Some(b"malformed")),
        Err(SspiError::Status { .. })
    ));
    assert!(matches!(
        client.step(Some(b"malformed")),
        Err(SspiError::InvalidState)
    ));
}

#[cfg(windows)]
#[test]
fn explicit_credentials_complete_ntlm_with_synthetic_local_type2() {
    let mut client = SspiClient::new(
        AuthScheme::Ntlm,
        "HTTP/proxy.example",
        Credentials::Explicit {
            username: "protocol-test",
            password: "not-a-real-secret",
            domain: Some("."),
        },
    )
    .unwrap();
    client.step(None).unwrap();
    // MS-NLMP CHALLENGE_MESSAGE: synthetic nonce and an empty TargetInfo list.
    // No real account/server is involved and no token bytes are logged.
    let mut challenge = vec![0; 60];
    challenge[..8].copy_from_slice(b"NTLMSSP\0");
    challenge[8..12].copy_from_slice(&2u32.to_le_bytes());
    challenge[16..20].copy_from_slice(&56u32.to_le_bytes());
    challenge[20..24].copy_from_slice(&0x0088_8201u32.to_le_bytes());
    challenge[24..32].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    challenge[40..42].copy_from_slice(&4u16.to_le_bytes());
    challenge[42..44].copy_from_slice(&4u16.to_le_bytes());
    challenge[44..48].copy_from_slice(&56u32.to_le_bytes());
    let token = client.step(Some(&challenge)).unwrap();
    assert!(token.complete);
    assert!(token.bytes.len() >= 12);
    assert_eq!(&token.bytes[..8], b"NTLMSSP\0");
    assert_eq!(
        u32::from_le_bytes(token.bytes[8..12].try_into().unwrap()),
        3
    );
}
