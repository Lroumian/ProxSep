//! Bounded Windows identity/adapter/WFP helpers. Never opens or loads a driver.
//!
//! WFP socket queries are synchronous (no OVERLAPPED or retained pointers). All
//! supplied buffers live through each call. IP Helper owns no returned memory:
//! its linked pointers are checked against the owned aligned allocation before
//! reading. Process handles have a unique RAII owner. TCP-table identification
//! is a snapshot, not an authenticated identity and can race process exit/PID
//! reuse; transparent capture should prefer the kernel EventRecord identity.
use proxsep_driver::EventRecord;
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
};
use tokio::net::{TcpSocket, TcpStream};

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Testable synchronous query state machine. Microsoft specifies error122 and
/// the required byte count for too-small redirect query buffers. WSAEFAULT10014
/// is a genuine invalid-pointer error and is not treated as buffer growth.
#[doc(hidden)]
pub fn query_redirect_with(
    mut call: impl FnMut(&mut [u8]) -> Result<usize, (i32, usize)>,
) -> io::Result<Vec<u8>> {
    let cap = proxsep_driver::EVENT_HEADER_SIZE + proxsep_driver::MAX_EVENT_EXTRA_BYTES;
    let mut wanted = 4096usize;
    for _ in 0..8 {
        let mut bytes = vec![0; wanted];
        match call(&mut bytes) {
            Ok(returned) if returned > 0 && returned <= wanted => {
                bytes.truncate(returned);
                return Ok(bytes);
            }
            Ok(_) => return Err(invalid("empty/oversized WFP socket result")),
            Err((122, required)) if required > wanted && required <= cap => wanted = required,
            Err((122, _)) => return Err(invalid("invalid/non-growing WFP required length")),
            Err((error, _)) => return Err(io::Error::from_raw_os_error(error)),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::WouldBlock,
        "WFP query retry limit",
    ))
}

fn decode_sockaddr(bytes: &[u8]) -> io::Result<SocketAddr> {
    if bytes.len() < 4 {
        return Err(invalid("short sockaddr"));
    }
    let family = u16::from_le_bytes([bytes[0], bytes[1]]);
    let port = u16::from_be_bytes([bytes[2], bytes[3]]);
    match family {
        2 if bytes.len() >= 16 => Ok(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7])),
            port,
        )),
        23 if bytes.len() >= 28 => {
            let mut address = [0; 16];
            address.copy_from_slice(&bytes[8..24]);
            let flow = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
            let scope = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
            Ok(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(address),
                port,
                flow,
                scope,
            )))
        }
        _ => Err(invalid("unsupported or short sockaddr family")),
    }
}

pub fn parse_event_destination(event: &EventRecord) -> io::Result<SocketAddr> {
    let address = decode_sockaddr(event.destination_sockaddr())?;
    if address.port() == 0 {
        return Err(invalid("zero destination port"));
    }
    Ok(address)
}

/// Decode the WFP UTF-16LE app-ID without lossy replacement or interior NULs.
/// The result may be a native device path, not a DOS drive-letter path.
pub fn decode_application_id(event: &EventRecord) -> io::Result<String> {
    let bytes = event.application_id();
    if !bytes.len().is_multiple_of(2) {
        return Err(invalid("odd UTF-16 app-ID length"));
    }
    let mut units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    while units.last() == Some(&0) {
        units.pop();
    }
    if units.contains(&0) {
        return Err(invalid("interior NUL in app-ID"));
    }
    String::from_utf16(&units).map_err(|_| invalid("invalid UTF-16 app-ID"))
}

/// Read-only DOS alias mapping, with component boundaries and longest native
/// prefix winning. Unknown native paths remain unchanged; this never changes
/// the PID/app-ID carried by the kernel identity record.
pub fn map_native_app_path(path: &str, mappings: &[(String, String)]) -> String {
    mappings
        .iter()
        .filter(|(native, _)| {
            !native.is_empty()
                && path
                    .get(..native.len())
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case(native))
                && (path.len() == native.len() || path.as_bytes().get(native.len()) == Some(&b'\\'))
        })
        .max_by_key(|(native, _)| native.len())
        .map_or_else(
            || path.to_owned(),
            |(native, dos)| format!("{dos}{}", &path[native.len()..]),
        )
}

/// QueryDosDevice may append undeleted prior targets. Only its first NUL-ended
/// target is the current DOS alias, so stale mappings must never become rules.
#[doc(hidden)]
pub fn decode_current_dos_target(units: &[u16]) -> io::Result<String> {
    let end = units
        .iter()
        .position(|&u| u == 0)
        .filter(|&end| end > 0)
        .ok_or_else(|| invalid("empty/unterminated DOS device target"))?;
    String::from_utf16(&units[..end]).map_err(|_| invalid("invalid DOS device mapping UTF-16"))
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::{
        ffi::c_void,
        mem::{offset_of, size_of},
        os::windows::io::AsRawSocket,
        ptr::{null, null_mut},
    };
    use windows_sys::Win32::Storage::FileSystem::QueryDosDeviceW;
    use windows_sys::Win32::{
        Foundation::{CloseHandle, ERROR_BUFFER_OVERFLOW, ERROR_INSUFFICIENT_BUFFER, HANDLE},
        NetworkManagement::{IpHelper::*, Ndis::IfOperStatusUp},
        Networking::WinSock::*,
        System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
        },
    };

    pub fn native_app_path_to_dos(path: &str) -> io::Result<String> {
        let mut mappings = Vec::new();
        for letter in b'A'..=b'Z' {
            let name = [letter as u16, b':' as u16, 0];
            let mut capacity = 1024usize;
            for _ in 0..8 {
                let mut targets = vec![0u16; capacity];
                // SAFETY: letter name is NUL terminated; owned initialized
                // output has capacity UTF-16 units and lives through the call.
                let returned = unsafe {
                    QueryDosDeviceW(name.as_ptr(), targets.as_mut_ptr(), capacity as u32)
                };
                if returned == 0 {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() == Some(2) {
                        break;
                    }
                    if error.raw_os_error() == Some(122) && capacity < 65536 {
                        capacity *= 2;
                        continue;
                    }
                    return Err(error);
                }
                if returned as usize > capacity {
                    return Err(invalid("oversized DOS device mapping"));
                }
                let native = decode_current_dos_target(&targets[..returned as usize])?;
                mappings.push((native, format!("{}:", letter as char)));
                break;
            }
        }
        Ok(map_native_app_path(path, &mappings))
    }
    const MAX_SYSTEM_BYTES: usize = 16 * 1024 * 1024;
    const MAX_WFP_BYTES: usize =
        proxsep_driver::EVENT_HEADER_SIZE + proxsep_driver::MAX_EVENT_EXTRA_BYTES;
    const QUERY_CONTEXT: u32 = 0x980000DD;
    const QUERY_RECORDS: u32 = 0x980000DC;
    const SET_RECORDS: u32 = 0x980000DE;

    struct Buffer {
        words: Vec<u64>,
        used: usize,
    }
    impl Buffer {
        fn new(bytes: usize) -> io::Result<Self> {
            if !(4..=MAX_SYSTEM_BYTES).contains(&bytes) {
                return Err(invalid("IP Helper size exceeds bounds"));
            }
            Ok(Self {
                words: vec![0; bytes.div_ceil(8)],
                used: bytes,
            })
        }
        fn pointer(&mut self) -> *mut c_void {
            self.words.as_mut_ptr().cast()
        }
        fn range(&self, pointer: *const c_void, length: usize) -> io::Result<&[u8]> {
            let base = self.words.as_ptr() as usize;
            let offset = (pointer as usize)
                .checked_sub(base)
                .ok_or_else(|| invalid("IP Helper pointer outside buffer"))?;
            if offset.checked_add(length).is_none_or(|end| end > self.used) {
                return Err(invalid("IP Helper range outside buffer"));
            }
            // SAFETY: storage is initialized, owned and range checked above.
            Ok(unsafe {
                std::slice::from_raw_parts(self.words.as_ptr().cast::<u8>().add(offset), length)
            })
        }
        fn read<T: Copy>(&self, pointer: *const T) -> io::Result<T> {
            self.range(pointer.cast(), size_of::<T>())?;
            // SAFETY: bounds checked. Windows-sys C structs contain raw pointers
            // and integer fields with no Rust invalid-value enum discriminants.
            Ok(unsafe { pointer.read_unaligned() })
        }
        fn name(&self, pointer: *const u8) -> io::Result<String> {
            let base = self.words.as_ptr() as usize;
            let offset = (pointer as usize)
                .checked_sub(base)
                .ok_or_else(|| invalid("adapter name outside buffer"))?;
            let available = self
                .used
                .checked_sub(offset)
                .ok_or_else(|| invalid("adapter name outside buffer"))?
                .min(256);
            let bytes = self.range(pointer.cast(), available)?;
            let end = bytes
                .iter()
                .position(|&b| b == 0)
                .ok_or_else(|| invalid("unterminated adapter name"))?;
            std::str::from_utf8(&bytes[..end])
                .map(str::to_owned)
                .map_err(|_| invalid("non-UTF8 adapter name"))
        }
    }

    pub fn interfaces() -> io::Result<HashMap<String, Vec<IpAddr>>> {
        let mut wanted = 15 * 1024usize;
        for _ in 0..8 {
            let mut buffer = Buffer::new(wanted)?;
            let mut count = wanted as u32;
            // SAFETY: aligned allocation has count bytes, synchronously filled.
            let status = unsafe {
                GetAdaptersAddresses(
                    AF_UNSPEC as u32,
                    GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                    null(),
                    buffer.pointer().cast(),
                    &mut count,
                )
            };
            if status == ERROR_BUFFER_OVERFLOW {
                wanted = count as usize;
                continue;
            }
            if status != 0 {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
            if count as usize > wanted {
                return Err(invalid("oversized adapter result"));
            }
            buffer.used = count as usize;
            let mut adapter = buffer.words.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
            let mut result = HashMap::new();
            let mut visited = 0;
            while !adapter.is_null() {
                visited += 1;
                if visited > 4096 {
                    return Err(invalid("adapter list cycle/limit"));
                }
                let current = buffer.read(adapter)?;
                if current.OperStatus == IfOperStatusUp {
                    let name = buffer.name(current.AdapterName)?;
                    let addresses = result.entry(name).or_insert_with(Vec::new);
                    let mut unicast = current.FirstUnicastAddress;
                    let mut seen = 0;
                    while !unicast.is_null() {
                        seen += 1;
                        if seen > 4096 {
                            return Err(invalid("unicast list cycle/limit"));
                        }
                        let address = buffer.read(unicast)?;
                        if address.DadState == IpDadStatePreferred
                            || address.DadState == IpDadStateDeprecated
                        {
                            let length = usize::try_from(address.Address.iSockaddrLength)
                                .map_err(|_| invalid("negative sockaddr length"))?;
                            let bytes = buffer.range(address.Address.lpSockaddr.cast(), length)?;
                            if let Ok(socket) = decode_sockaddr(bytes)
                                && !addresses.contains(&socket.ip())
                            {
                                addresses.push(socket.ip());
                            }
                        }
                        unicast = address.Next;
                    }
                }
                adapter = current.Next;
            }
            return Ok(result);
        }
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "adapter table keeps growing",
        ))
    }

    fn tcp_table(family: u32) -> io::Result<Buffer> {
        let mut wanted = 16 * 1024usize;
        for _ in 0..8 {
            let mut buffer = Buffer::new(wanted)?;
            let mut count = wanted as u32;
            // SAFETY: DWORD-size API writes only within the owned allocation.
            let status = unsafe {
                GetExtendedTcpTable(
                    buffer.pointer(),
                    &mut count,
                    0,
                    family,
                    TCP_TABLE_OWNER_PID_ALL,
                    0,
                )
            };
            if status == ERROR_INSUFFICIENT_BUFFER {
                wanted = count as usize;
                continue;
            }
            if status != 0 {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
            if count as usize > wanted {
                return Err(invalid("oversized TCP table"));
            }
            buffer.used = count as usize;
            return Ok(buffer);
        }
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "TCP table keeps growing",
        ))
    }

    fn rows<T: Copy>(buffer: &Buffer, offset: usize) -> io::Result<Vec<T>> {
        let base = buffer.words.as_ptr().cast::<u8>();
        let count: u32 = buffer.read(base.cast())?;
        let bytes = (count as usize)
            .checked_mul(size_of::<T>())
            .ok_or_else(|| invalid("TCP row count overflow"))?;
        // SAFETY: adding a small C struct offset remains in the allocation;
        // range then checks the entire variable-length table before any read.
        let start = unsafe { base.add(offset) };
        buffer.range(start.cast(), bytes)?;
        let mut result = Vec::with_capacity(count as usize);
        for index in 0..count as usize {
            result.push(buffer.read(unsafe { start.add(index * size_of::<T>()).cast::<T>() })?);
        }
        Ok(result)
    }

    struct Process(HANDLE);
    impl Drop for Process {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    fn image(pid: u32) -> io::Result<String> {
        // SAFETY: read-only process handle uniquely owned by Process wrapper.
        let process = Process(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) });
        if process.0.is_null() {
            return Err(io::Error::last_os_error());
        }
        let mut buffer = vec![0u16; 32768];
        let mut length = buffer.len() as u32;
        if unsafe { QueryFullProcessImageNameW(process.0, 0, buffer.as_mut_ptr(), &mut length) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        if length as usize > buffer.len() {
            return Err(invalid("oversized process image"));
        }
        String::from_utf16(&buffer[..length as usize])
            .map_err(|_| invalid("invalid process image UTF-16"))
    }

    pub fn identify_client(stream: &TcpStream) -> io::Result<(u32, String)> {
        // Accepted connection tuple is reversed relative to the client row.
        let client = stream.peer_addr()?;
        let server = stream.local_addr()?;
        let pid = match (client, server) {
            (SocketAddr::V4(client), SocketAddr::V4(server)) => {
                let table = tcp_table(AF_INET as u32)?;
                rows::<MIB_TCPROW_OWNER_PID>(&table, offset_of!(MIB_TCPTABLE_OWNER_PID, table))?
                    .into_iter()
                    .find(|row| {
                        row.dwLocalAddr.to_ne_bytes() == client.ip().octets()
                            && row.dwRemoteAddr.to_ne_bytes() == server.ip().octets()
                            && u16::from_be(row.dwLocalPort as u16) == client.port()
                            && u16::from_be(row.dwRemotePort as u16) == server.port()
                    })
                    .map(|row| row.dwOwningPid)
            }
            (SocketAddr::V6(client), SocketAddr::V6(server)) => {
                let table = tcp_table(AF_INET6 as u32)?;
                rows::<MIB_TCP6ROW_OWNER_PID>(&table, offset_of!(MIB_TCP6TABLE_OWNER_PID, table))?
                    .into_iter()
                    .find(|row| {
                        row.ucLocalAddr == client.ip().octets()
                            && row.ucRemoteAddr == server.ip().octets()
                            && row.dwLocalScopeId == client.scope_id()
                            && row.dwRemoteScopeId == server.scope_id()
                            && u16::from_be(row.dwLocalPort as u16) == client.port()
                            && u16::from_be(row.dwRemotePort as u16) == server.port()
                    })
                    .map(|row| row.dwOwningPid)
            }
            _ => return Err(invalid("mixed TCP tuple family")),
        }
        .filter(|&pid| pid != 0)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "TCP client tuple no longer present",
            )
        })?;
        Ok((pid, image(pid)?))
    }

    fn query(socket: SOCKET, code: u32) -> io::Result<Vec<u8>> {
        query_redirect_with(|bytes| {
            let mut returned = 0;
            // SAFETY: synchronous WSAIoctl with no callback; socket is borrowed
            // and both initialized output/returned storage live for this call.
            let status = unsafe {
                WSAIoctl(
                    socket,
                    code,
                    null(),
                    0,
                    bytes.as_mut_ptr().cast(),
                    bytes.len() as u32,
                    &mut returned,
                    null_mut(),
                    None,
                )
            };
            if status == 0 {
                Ok(returned as usize)
            } else {
                Err((unsafe { WSAGetLastError() }, returned as usize))
            }
        })
    }
    pub fn redirect_context(stream: &TcpStream) -> io::Result<EventRecord> {
        EventRecord::decode(&query(stream.as_raw_socket() as SOCKET, QUERY_CONTEXT)?)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }
    pub fn redirect_records(stream: &TcpStream) -> io::Result<Vec<u8>> {
        query(stream.as_raw_socket() as SOCKET, QUERY_RECORDS)
    }
    pub fn set_redirect_records(socket: &TcpSocket, bytes: &[u8]) -> io::Result<()> {
        if bytes.is_empty() || bytes.len() > MAX_WFP_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "WFP records empty/too large",
            ));
        }
        let mut returned = 0;
        // SAFETY: synchronous call, no retained buffers, caller owns socket.
        let status = unsafe {
            WSAIoctl(
                socket.as_raw_socket() as SOCKET,
                SET_RECORDS,
                bytes.as_ptr().cast(),
                bytes.len() as u32,
                null_mut(),
                0,
                &mut returned,
                null_mut(),
                None,
            )
        };
        if status == 0 {
            Ok(())
        } else {
            Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }))
        }
    }
}

#[cfg(windows)]
pub use platform::{
    identify_client, interfaces, native_app_path_to_dos, redirect_context, redirect_records,
    set_redirect_records,
};

#[cfg(not(windows))]
fn unsupported<T>() -> io::Result<T> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "Windows network/WFP API unavailable",
    ))
}
#[cfg(not(windows))]
pub fn interfaces() -> io::Result<HashMap<String, Vec<IpAddr>>> {
    unsupported()
}
#[cfg(not(windows))]
pub fn identify_client(_: &TcpStream) -> io::Result<(u32, String)> {
    unsupported()
}
#[cfg(not(windows))]
pub fn redirect_context(_: &TcpStream) -> io::Result<EventRecord> {
    unsupported()
}
#[cfg(not(windows))]
pub fn redirect_records(_: &TcpStream) -> io::Result<Vec<u8>> {
    unsupported()
}
#[cfg(not(windows))]
pub fn set_redirect_records(_: &TcpSocket, _: &[u8]) -> io::Result<()> {
    unsupported()
}
#[cfg(not(windows))]
pub fn native_app_path_to_dos(_: &str) -> io::Result<String> {
    unsupported()
}
