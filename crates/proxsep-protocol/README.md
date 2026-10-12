# Proxy protocol clients

This crate implements SOCKS4/4a CONNECT, SOCKS5 CONNECT and UDP ASSOCIATE,
SOCKS5 username/password authentication, and HTTP CONNECT with optional Basic
authentication. The public `negotiate` functions remain compatible with the
initial crate. Their `_with_timeout` variants bound the whole handshake; discard
the stream after a failed or timed-out handshake.

`socks5::UdpAssociation` owns a TCP control connection and a connected UDP socket.
`connect(proxy_host, proxy_port, credentials, timeout)` establishes the association;
`send(host, port, payload, timeout)` returns payload bytes sent;
`recv(timeout)` returns `ReceivedUdpDatagram { source, payload }`.
The connected socket accepts packets only from the negotiated relay endpoint.
TCP control closure invalidates the association. Dropping or shutting down it
terminates the TCP control connection. Receive timeouts leave the association open.

`socks5::associate_udp` supports callers that manage their own sockets; callers
must keep its control stream open. `encode_udp_datagram` and `decode_udp_datagram`
support IPv4, IPv6, and domain-name endpoints. Fragmented datagrams are rejected;
RFC 1928 makes SOCKS-level fragmentation optional. Outgoing packets are bounded
to the portable 65,507-byte UDP payload limit, including the SOCKS header.

SOCKS4 hostnames use SOCKS4a remote resolution. For ordinary SOCKS4 with local
resolution, resolve the name first and pass an IPv4 literal. IPv6 destinations
are unsupported by SOCKS4. SOCKS5 credentials must each be 1–255 bytes per RFC
1929. HTTP hosts are IP literals or ASCII names; callers must convert IDNs to
their ASCII form. Basic-auth usernames cannot contain a colon.

HTTP CONNECT accepts HTTP/1.0 or HTTP/1.1 replies, validates status lines and
header fields, handles up to 31 interim responses, and limits combined headers
to 64 KiB. It reads only through the final header delimiter, preserving tunnel
bytes already received. Successful CONNECT ignores response Content-Length and
Transfer-Encoding as specified by RFC 9110.

Sources used for wire formats and validation:

- [RFC 1928: SOCKS5](https://www.rfc-editor.org/rfc/rfc1928)
- [RFC 1929: Username/password authentication](https://www.rfc-editor.org/rfc/rfc1929)
- [Original SOCKS4 specification](https://www.openssh.org/txt/socks4.protocol)
- [Original SOCKS4a extension](https://www.openssh.org/txt/socks4a.protocol)
- [RFC 9110: CONNECT semantics](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6)
- [RFC 9112: HTTP/1.1 syntax](https://www.rfc-editor.org/rfc/rfc9112.html)

These are protocol implementations with local conformance tests. They do not
establish byte-for-byte Proxifier behavior for malformed responses, authentication
fallback, or the unspecified UDP relay-address compatibility convention. BIND,
GSSAPI, NTLM/Negotiate, and HTTPS-to-proxy transport are not implemented here.
