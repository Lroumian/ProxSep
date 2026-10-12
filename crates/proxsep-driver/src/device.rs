//! Explicit, cancellable user-mode device access. Tests never open a device.

use std::io;

#[derive(Debug)]
pub struct DriverDevice {
    #[cfg(windows)]
    file: std::fs::File,
}

impl DriverDevice {
    /// Opening the device must be an explicit caller action. This does not
    /// install, start, or load the driver service.
    pub fn open() -> io::Result<Self> {
        Self::open_path(r"\\.\ProxifierDrv")
    }

    /// Explicit caller-selected device only. Restricts names to the DOS device
    /// namespace (no filesystem or pipe paths); never installs/loads a service.
    pub fn open_path(path: &str) -> io::Result<Self> {
        let name = path.strip_prefix(r"\\.\").ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "expected DOS device path")
        })?;
        if name.is_empty()
            || name.len() > 128
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid DOS device name",
            ));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .share_mode(0)
                .custom_flags(0x40000000)
                .open(path)?;
            Ok(Self { file })
        }
        #[cfg(not(windows))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "driver device requires Windows",
            ))
        }
    }

    /// Default bounded operation. Timeout cancels and drains the pending I/O.
    pub fn ioctl(&self, code: u32, input: &[u8], output: &mut [u8]) -> io::Result<usize> {
        self.ioctl_timeout(code, input, output, std::time::Duration::from_secs(30))
    }

    pub fn ioctl_timeout(
        &self,
        code: u32,
        input: &[u8],
        output: &mut [u8],
        timeout: std::time::Duration,
    ) -> io::Result<usize> {
        #[cfg(windows)]
        {
            use std::ffi::c_void;
            use std::os::windows::io::AsRawHandle;
            #[repr(C)]
            struct Overlapped {
                internal: usize,
                internal_high: usize,
                offset: u32,
                offset_high: u32,
                event: *mut c_void,
            }
            #[link(name = "kernel32")]
            unsafe extern "system" {
                fn DeviceIoControl(
                    device: *mut c_void,
                    code: u32,
                    input: *const c_void,
                    input_len: u32,
                    output: *mut c_void,
                    output_len: u32,
                    returned: *mut u32,
                    overlapped: *mut Overlapped,
                ) -> i32;
                fn CreateEventW(
                    attributes: *const c_void,
                    manual_reset: i32,
                    initial_state: i32,
                    name: *const u16,
                ) -> *mut c_void;
                fn CloseHandle(handle: *mut c_void) -> i32;
                fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
                fn CancelIoEx(device: *mut c_void, overlapped: *mut Overlapped) -> i32;
                fn GetOverlappedResult(
                    device: *mut c_void,
                    overlapped: *mut Overlapped,
                    returned: *mut u32,
                    wait: i32,
                ) -> i32;
            }
            struct Event(*mut c_void);
            impl Drop for Event {
                fn drop(&mut self) {
                    // SAFETY: This wrapper uniquely owns the CreateEventW handle.
                    unsafe {
                        CloseHandle(self.0);
                    }
                }
            }
            let input_len = u32::try_from(input.len()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "IOCTL input exceeds u32 length",
                )
            })?;
            let output_len = u32::try_from(output.len()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "IOCTL output exceeds u32 length",
                )
            })?;
            // SAFETY: Null attributes/name request a private non-inheritable event.
            let event = Event(unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) });
            if event.0.is_null() {
                return Err(io::Error::last_os_error());
            }
            let mut overlapped = Overlapped {
                internal: 0,
                internal_high: 0,
                offset: 0,
                offset_high: 0,
                event: event.0,
            };
            let mut returned = 0;
            // SAFETY: File and slices live through completion; every pending
            // path below completes or cancels AND drains before returning.
            let success = unsafe {
                DeviceIoControl(
                    self.file.as_raw_handle(),
                    code,
                    input.as_ptr().cast(),
                    input_len,
                    output.as_mut_ptr().cast(),
                    output_len,
                    std::ptr::null_mut(),
                    &mut overlapped,
                )
            };
            if success == 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(997) {
                    return Err(error);
                }
                let wait_ms = timeout.as_millis().min((u32::MAX - 1) as u128) as u32;
                // SAFETY: The event belongs to this pending operation.
                let wait_result = unsafe { WaitForSingleObject(event.0, wait_ms) };
                if wait_result != 0 {
                    let error = if wait_result == 258 {
                        io::Error::new(io::ErrorKind::TimedOut, "driver IOCTL timed out")
                    } else {
                        io::Error::last_os_error()
                    };
                    // SAFETY: Cancel only this operation; drain even if cancellation
                    // races completion. Buffer/OVERLAPPED storage stays live.
                    unsafe {
                        CancelIoEx(self.file.as_raw_handle(), &mut overlapped);
                        GetOverlappedResult(
                            self.file.as_raw_handle(),
                            &mut overlapped,
                            &mut returned,
                            1,
                        );
                    }
                    return Err(error);
                }
            }
            // SAFETY: Immediate success or signaled event; obtain byte count
            // from OVERLAPPED even when DeviceIoControl completed immediately.
            let completed = unsafe {
                GetOverlappedResult(self.file.as_raw_handle(), &mut overlapped, &mut returned, 1)
            };
            if completed == 0 {
                return Err(io::Error::last_os_error());
            }
            if returned as usize > output.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "driver returned length exceeds output buffer",
                ));
            }
            Ok(returned as usize)
        }
        #[cfg(not(windows))]
        {
            let _ = (code, input, output, timeout);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "driver device requires Windows",
            ))
        }
    }

    pub fn version(&self) -> io::Result<u32> {
        let mut output = [0; 4];
        if self.ioctl(super::IOCTL_VERSION, &[], &mut output)? != 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid driver version response size",
            ));
        }
        Ok(u32::from_le_bytes(output))
    }

    pub fn configure(&self, config: &super::DriverConfig) -> io::Result<()> {
        self.ioctl(super::IOCTL_CONFIGURE, config.as_bytes(), &mut [])?;
        Ok(())
    }

    /// Only for ProxSepDrv. Its separate magic/version/size ABI is not an
    /// original-driver config and should never be sent to ProxifierDrv.
    pub fn configure_independent(&self, config: &super::IndependentConfig) -> io::Result<()> {
        self.ioctl(
            super::IOCTL_CONFIGURE_INDEPENDENT,
            config.as_bytes(),
            &mut [],
        )
        .map(|_| ())
    }

    pub fn start(&self) -> io::Result<()> {
        self.ioctl(super::IOCTL_START, &[], &mut [])?;
        Ok(())
    }
    pub fn stop(&self) -> io::Result<()> {
        self.ioctl(super::IOCTL_STOP, &[], &mut [])?;
        Ok(())
    }

    pub fn poll_event(&self, timeout: std::time::Duration) -> io::Result<super::EventRecord> {
        let mut output = vec![0; super::EVENT_HEADER_SIZE + super::MAX_EVENT_EXTRA_BYTES];
        let size = self.ioctl_timeout(super::IOCTL_POLL_EVENT, &[], &mut output, timeout)?;
        super::EventRecord::decode(&output[..size])
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    pub fn classify_response(
        &self,
        event: &super::EventRecord,
        flags: u32,
        destination: Option<&[u8]>,
    ) -> io::Result<()> {
        let input = event
            .classify_response(flags, destination)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        self.ioctl(super::IOCTL_CLASSIFY_RESPONSE, &input, &mut [])?;
        Ok(())
    }

    pub fn inject_datagram(&self, request: &super::DatagramInjection) -> io::Result<()> {
        self.ioctl(super::IOCTL_INJECT_DATAGRAM, &request.encode(), &mut [])?;
        Ok(())
    }

    pub fn counters(&self) -> io::Result<super::DriverCounters> {
        let mut output = [0; 12];
        let size = self.ioctl(super::IOCTL_COUNTERS, &[], &mut output)?;
        super::DriverCounters::decode(&output[..size])
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }
}
