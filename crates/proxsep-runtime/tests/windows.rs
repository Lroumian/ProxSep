use proxsep_driver::EventRecord;
use proxsep_runtime::windows::{decode_application_id, parse_event_destination};
#[test]
fn native_path_mapping_is_case_insensitive_longest_and_component_bounded() {
    use proxsep_runtime::windows::map_native_app_path;
    let mappings = vec![
        (r"\Device\HarddiskVolume2".into(), "C:".into()),
        (r"\Device\HarddiskVolume2\mounted".into(), "D:".into()),
    ];
    assert_eq!(
        map_native_app_path(r"\device\harddiskvolume2\mounted\App.exe", &mappings),
        r"D:\App.exe"
    );
    assert_eq!(
        map_native_app_path(r"\Device\HarddiskVolume20\App.exe", &mappings),
        r"\Device\HarddiskVolume20\App.exe"
    );
    assert_eq!(map_native_app_path(r"C:\App.exe", &mappings), r"C:\App.exe");
    assert_eq!(
        map_native_app_path(r"\Device\HarddiskVolume2\app.exe", &mappings),
        r"C:\app.exe"
    );
}

#[test]
fn dos_device_current_mapping_ignores_prior_undeleted_targets() {
    use proxsep_runtime::windows::decode_current_dos_target;
    let returned: Vec<u16> = r"\Device\Current"
        .encode_utf16()
        .chain([0])
        .chain(r"\Device\Old".encode_utf16())
        .chain([0, 0])
        .collect();
    assert_eq!(
        decode_current_dos_target(&returned).unwrap(),
        r"\Device\Current"
    );
    assert!(decode_current_dos_target(&[0]).is_err());
    assert!(decode_current_dos_target(&[65]).is_err());
    assert!(decode_current_dos_target(&[0xd800, 0]).is_err());
}
#[test]
fn wfp_query_retries_required122_but_not_pointer_errors_or_invalid_sizes() {
    use proxsep_runtime::windows::query_redirect_with;
    let mut calls = 0;
    let result = query_redirect_with(|buffer| {
        calls += 1;
        if calls == 1 {
            assert_eq!(buffer.len(), 4096);
            Err((122, 8192))
        } else {
            assert_eq!(buffer.len(), 8192);
            buffer[..3].copy_from_slice(b"abc");
            Ok(3)
        }
    })
    .unwrap();
    assert_eq!(result, b"abc");
    assert_eq!(calls, 2);
    for size in [0, 4096, 2_000_000] {
        assert!(query_redirect_with(|_| Err((122, size))).is_err());
    }
    let mut errors = 0;
    assert_eq!(
        query_redirect_with(|_| {
            errors += 1;
            Err((10014, 8192))
        })
        .unwrap_err()
        .raw_os_error(),
        Some(10014)
    );
    assert_eq!(errors, 1);
    assert!(query_redirect_with(|buffer| Ok(buffer.len() + 1)).is_err());
    let mut attempts = 0;
    assert_eq!(
        query_redirect_with(|buffer| {
            attempts += 1;
            Err((122, buffer.len() + 1))
        })
        .unwrap_err()
        .kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(attempts, 8);
}

#[test]
fn sockaddr_and_utf16_fixtures() {
    let app: Vec<u8> = "\\Device\\HarddiskVolume3\\app.exe\0"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    let mut wire = EventRecord::new(2, &app, &[]).unwrap().encode();
    wire[276..278].copy_from_slice(&23u16.to_le_bytes());
    wire[278..280].copy_from_slice(&443u16.to_be_bytes());
    wire[284..300].copy_from_slice(&"fe80::1234".parse::<std::net::Ipv6Addr>().unwrap().octets());
    wire[300..304].copy_from_slice(&7u32.to_le_bytes());
    let event = EventRecord::decode(&wire).unwrap();
    let addr = parse_event_destination(&event).unwrap();
    assert_eq!(
        addr,
        "[fe80::1234%7]:443"
            .parse::<std::net::SocketAddr>()
            .unwrap()
    );
    wire[280..284].copy_from_slice(&0x12345678u32.to_le_bytes());
    let std::net::SocketAddr::V6(with_flow) =
        parse_event_destination(&EventRecord::decode(&wire).unwrap()).unwrap()
    else {
        panic!("expected IPv6");
    };
    assert_eq!(with_flow.flowinfo(), 0x12345678);
    assert_eq!(with_flow.scope_id(), 7);
    assert_eq!(
        decode_application_id(&event).unwrap(),
        "\\Device\\HarddiskVolume3\\app.exe"
    );
    wire[276..278].copy_from_slice(&2u16.to_le_bytes());
    wire[280..284].copy_from_slice(&[1, 2, 3, 4]);
    assert_eq!(
        parse_event_destination(&EventRecord::decode(&wire).unwrap()).unwrap(),
        "1.2.3.4:443".parse::<std::net::SocketAddr>().unwrap()
    );
    assert!(decode_application_id(&EventRecord::new(2, &[1], &[]).unwrap()).is_err());
    assert!(decode_application_id(&EventRecord::new(2, &[0x00, 0xd8], &[]).unwrap()).is_err());
    assert!(
        decode_application_id(&EventRecord::new(2, &[65, 0, 0, 0, 66, 0], &[]).unwrap()).is_err()
    );
    wire[276..278].copy_from_slice(&99u16.to_le_bytes());
    assert!(parse_event_destination(&EventRecord::decode(&wire).unwrap()).is_err());
    wire[276..278].copy_from_slice(&2u16.to_le_bytes());
    wire[278..280].fill(0);
    assert!(parse_event_destination(&EventRecord::decode(&wire).unwrap()).is_err());
}

#[cfg(windows)]
#[tokio::test]
async fn reverse_tuple_and_plain_socket_context() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (accepted, _) = listener.accept().await.unwrap();
    let (pid, image) = proxsep_runtime::windows::identify_client(&accepted).unwrap();
    assert_eq!(pid, std::process::id());
    assert!(image.to_ascii_lowercase().ends_with(".exe"));
    assert!(proxsep_runtime::windows::redirect_context(&accepted).is_err());
    assert!(proxsep_runtime::windows::redirect_records(&accepted).is_err());
    drop(client);
}

#[cfg(windows)]
#[tokio::test]
async fn ipv6_reverse_tuple_and_active_interfaces() {
    let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
    let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (accepted, _) = listener.accept().await.unwrap();
    assert_eq!(
        proxsep_runtime::windows::identify_client(&accepted)
            .unwrap()
            .0,
        std::process::id()
    );
    let adapters = proxsep_runtime::windows::interfaces().unwrap();
    assert!(adapters.values().flatten().any(|ip| ip.is_loopback()));
    drop(client);
}
