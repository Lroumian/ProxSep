use proxsep_core::{
    dns::{DnsDecision, DnsMode, DnsPolicy, DnsResolver, FakeIpMap, decode_name, parse_query},
    profile::ResolveOptions,
};
use std::net::Ipv4Addr;

fn options() -> ResolveOptions {
    ResolveOptions {
        auto_mode_detection: false,
        via_proxy: true,
        exclusion_list: "%ComputerName%; %SimpleHostnames%; *.local; safe?.example".into(),
        ..ResolveOptions::default()
    }
}

fn query(host: &str, qtype: u16) -> Vec<u8> {
    let mut packet = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in host.split('.') {
        packet.push(label.len() as u8);
        packet.extend(label.as_bytes());
    }
    packet.push(0);
    packet.extend(qtype.to_be_bytes());
    packet.extend([0, 1]);
    packet
}

#[test]
fn policy_masks_macros_and_only_list_mode() {
    let policy = DnsPolicy::new(options(), "Workstation");
    for host in ["WORKSTATION", "printer", "name.local", "safe1.example"] {
        assert_eq!(policy.mode_for_host(host).unwrap(), DnsMode::Local);
    }
    assert_eq!(
        policy.mode_for_host("outside.example.").unwrap(),
        DnsMode::Remote
    );
    assert_eq!(policy.mode_for_host("192.0.2.1").unwrap(), DnsMode::Local);
    let policy = DnsPolicy::new(
        ResolveOptions {
            exclusion_only_from_list: true,
            ..options()
        },
        "Workstation",
    );
    assert_eq!(policy.mode_for_host("name.local").unwrap(), DnsMode::Remote);
    assert_eq!(
        policy.mode_for_host("outside.example").unwrap(),
        DnsMode::Local
    );
}

#[test]
fn auto_detection_transitions_override_manual_default_without_duplicates() {
    let mut policy = DnsPolicy::new(
        ResolveOptions {
            auto_mode_detection: true,
            via_proxy: false,
            exclusion_list: String::new(),
            ..options()
        },
        "computer",
    );
    assert_eq!(policy.mode_for_host("example.com").unwrap(), DnsMode::Local);
    let change = policy.observe_local_dns(false).unwrap();
    assert_eq!(change.old, DnsMode::Local);
    assert_eq!(change.new, DnsMode::Remote);
    assert!(policy.observe_local_dns(false).is_none());
    assert_eq!(
        policy.mode_for_host("example.com").unwrap(),
        DnsMode::Remote
    );
    assert_eq!(policy.observe_local_dns(true).unwrap().new, DnsMode::Local);
    let mut manual = DnsPolicy::new(options(), "computer");
    assert!(manual.observe_local_dns(true).is_none());
    assert_eq!(
        manual.mode_for_host("example.com").unwrap(),
        DnsMode::Remote
    );
}

#[test]
fn fake_addresses_are_stable_case_insensitive_and_never_reassigned() {
    let mut map = FakeIpMap::new(2).unwrap();
    let first = map.get_or_allocate("Example.COM.").unwrap();
    assert_eq!(first, Ipv4Addr::new(127, 8, 0, 1));
    assert_eq!(map.get_or_allocate("example.com").unwrap(), first);
    let second = map.get_or_allocate("second.example").unwrap();
    assert_ne!(first, second);
    assert!(map.get_or_allocate("third.example").is_err());
    assert_eq!(map.reverse(first), Some("example.com"));
    assert_eq!(map.reverse(second), Some("second.example"));
    assert_eq!(map.reverse(Ipv4Addr::new(127, 8, 0, 255)), None);
    assert!(map.get_or_allocate("bad..example").is_err());
}

#[test]
fn query_parser_checks_header_counts_names_and_edns_bounds() {
    let packet = query("Example.COM", 1);
    let question = parse_query(&packet).unwrap();
    assert_eq!(question.host, "Example.COM");
    assert_eq!(question.qtype, 1);
    assert_eq!(question.transaction_id, 0x1234);
    for length in 0..packet.len() {
        assert!(parse_query(&packet[..length]).is_err());
    }
    let mut duplicate = packet.clone();
    duplicate[5] = 2;
    assert!(parse_query(&duplicate).is_err());
    let mut response = packet.clone();
    response[2] |= 128;
    assert!(parse_query(&response).is_err());
    let mut extra = packet.clone();
    extra.push(1);
    assert!(parse_query(&extra).is_err());
    let mut edns = packet.clone();
    edns[11] = 1;
    edns.extend([0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
    assert_eq!(parse_query(&edns).unwrap().host, "Example.COM");
    edns.pop();
    assert!(parse_query(&edns).is_err());
}

#[test]
fn compression_decoding_rejects_cycles_pointers_and_long_names() {
    let mut packet = query("example.com", 1);
    let offset = packet.len();
    packet.extend([0xc0, 12]);
    assert_eq!(
        decode_name(&packet, offset).unwrap(),
        ("example.com".into(), offset + 2)
    );
    assert!(decode_name(&[0xc0, 0], 0).is_err());
    assert!(decode_name(&[0xc0, 2, 0xc0, 0], 0).is_err());
    assert!(decode_name(&[0xc0, 255], 0).is_err());
    assert!(decode_name(&[0x40, 0], 0).is_err());
    let long = [
        vec![63],
        vec![b'a'; 63],
        vec![63],
        vec![b'b'; 63],
        vec![63],
        vec![b'c'; 63],
        vec![63],
        vec![b'd'; 63],
        vec![0],
    ]
    .concat();
    assert!(decode_name(&long, 0).is_err());
}

#[test]
fn remote_a_answer_has_transaction_question_and_fake_address() {
    let mut resolver = DnsResolver::new(
        DnsPolicy::new(options(), "computer"),
        FakeIpMap::new(10).unwrap(),
        60,
    );
    let packet = query("example.com", 1);
    let DnsDecision::Answer(response) = resolver.handle_query(&packet).unwrap() else {
        panic!("expected fake answer")
    };
    assert_eq!(&response[..2], &[0x12, 0x34]);
    assert_eq!(response[2] & 0x80, 0x80);
    assert_eq!(&response[4..8], &[0, 1, 0, 1]);
    assert_eq!(&response[12..packet.len()], &packet[12..]);
    assert_eq!(&response[response.len() - 4..], &[127, 8, 0, 1]);
    let DnsDecision::Forward { mode, question } =
        resolver.handle_query(&query("printer", 1)).unwrap()
    else {
        panic!("expected local forwarding")
    };
    assert_eq!(mode, DnsMode::Local);
    assert_eq!(question.host, "printer");
}

#[test]
fn non_a_queries_are_explicitly_forwarded_or_answered_without_fake_ipv6() {
    let mut resolver = DnsResolver::new(
        DnsPolicy::new(options(), "computer"),
        FakeIpMap::new(10).unwrap(),
        60,
    );
    assert!(matches!(
        resolver.handle_query(&query("example.com", 28)).unwrap(),
        DnsDecision::Forward {
            mode: DnsMode::Remote,
            ..
        }
    ));
    let mut resolver = DnsResolver::new(
        DnsPolicy::new(
            ResolveOptions {
                block_non_a_types: true,
                ..options()
            },
            "computer",
        ),
        FakeIpMap::new(10).unwrap(),
        60,
    );
    for qtype in [28, 16, 15] {
        let DnsDecision::Answer(response) =
            resolver.handle_query(&query("example.com", qtype)).unwrap()
        else {
            panic!("expected NODATA")
        };
        assert_eq!(&response[6..8], &[0, 0]);
        assert_eq!(response[3] & 15, 0);
    }
}

#[test]
fn malformed_and_exhausted_queries_produce_error_responses() {
    let mut resolver = DnsResolver::new(
        DnsPolicy::new(options(), "computer"),
        FakeIpMap::new(1).unwrap(),
        60,
    );
    let DnsDecision::Answer(response) = resolver.handle_datagram(&[0x12, 0x34, 1]) else {
        panic!("error answer required")
    };
    assert_eq!(&response[..2], &[0x12, 0x34]);
    assert_eq!(response[3] & 15, 1);
    resolver.handle_query(&query("first.example", 1)).unwrap();
    let DnsDecision::Answer(response) = resolver.handle_datagram(&query("second.example", 1))
    else {
        panic!("SERVFAIL required")
    };
    assert_eq!(response[3] & 15, 2);
}

#[test]
fn compression_pointer_cannot_target_dns_header() {
    let packet = [
        vec![0, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0],
        vec![0xc0, 0, 0, 1, 0, 1],
    ]
    .concat();
    assert!(parse_query(&packet).is_err());
}

#[test]
fn dns_datagram_loopback_returns_fake_a_answer() {
    use std::{net::UdpSocket, time::Duration};
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = server.local_addr().unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let peer = std::thread::spawn(move || {
        let mut resolver = DnsResolver::new(
            DnsPolicy::new(options(), "computer"),
            FakeIpMap::new(10).unwrap(),
            60,
        );
        let mut buffer = [0; 512];
        let (length, sender) = server.recv_from(&mut buffer).unwrap();
        let DnsDecision::Answer(response) = resolver.handle_datagram(&buffer[..length]) else {
            panic!("answer required")
        };
        server.send_to(&response, sender).unwrap();
    });
    let client = UdpSocket::bind("127.0.0.1:0").unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    client.send_to(&query("example.com", 1), address).unwrap();
    let mut buffer = [0; 512];
    let (length, source) = client.recv_from(&mut buffer).unwrap();
    assert_eq!(source, address);
    assert_eq!(&buffer[..2], &[0x12, 0x34]);
    assert_eq!(&buffer[length - 4..length], &[127, 8, 0, 1]);
    peer.join().unwrap();
}
