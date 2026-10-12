use base64::{Engine as _, engine::general_purpose::STANDARD};

const ACCOUNT_PREFIX: [u8; 2] = [0, 1];
const MAX_PASSWORD_UTF16: usize = 256;
const MAX_CARRIER_BYTES: usize = 1124;

#[cfg(windows)]
#[repr(C)]
struct DataBlob {
    size: u32,
    data: *mut u8,
}

#[cfg(windows)]
#[link(name = "Crypt32")]
unsafe extern "system" {
    fn CryptProtectData(
        input: *mut DataBlob,
        description: *const u16,
        entropy: *mut DataBlob,
        reserved: *mut core::ffi::c_void,
        prompt: *mut core::ffi::c_void,
        flags: u32,
        output: *mut DataBlob,
    ) -> i32;
    fn CryptUnprotectData(
        input: *mut DataBlob,
        description: *mut *mut u16,
        entropy: *mut DataBlob,
        reserved: *mut core::ffi::c_void,
        prompt: *mut core::ffi::c_void,
        flags: u32,
        output: *mut DataBlob,
    ) -> i32;
}

#[cfg(windows)]
#[link(name = "Kernel32")]
unsafe extern "system" {
    fn GetLastError() -> u32;
    fn LocalFree(memory: *mut core::ffi::c_void) -> *mut core::ffi::c_void;
}

#[cfg(windows)]
struct LocalAllocation {
    pointer: *mut u8,
    clear_len: usize,
}

#[cfg(windows)]
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.pointer.is_null() {
            unsafe {
                if self.clear_len != 0 {
                    core::ptr::write_bytes(self.pointer, 0, self.clear_len);
                }
                LocalFree(self.pointer.cast());
            }
        }
    }
}

#[cfg(windows)]
fn last_error(operation: &str) -> String {
    format!("{operation} failed with Windows error {}", unsafe {
        GetLastError()
    })
}

#[cfg(windows)]
pub(crate) fn protect_account(value: &str) -> Result<String, String> {
    let mut utf16: Vec<u16> = value.encode_utf16().collect();
    if utf16.len() > MAX_PASSWORD_UTF16 {
        return Err("credential exceeds 256 UTF-16 code units".into());
    }
    utf16.push(0);
    let mut input_bytes = Vec::with_capacity(utf16.len() * 2);
    for unit in &utf16 {
        input_bytes.extend_from_slice(&unit.to_le_bytes());
    }
    let mut input = DataBlob {
        size: u32::try_from(input_bytes.len()).map_err(|_| "credential is too large")?,
        data: input_bytes.as_mut_ptr(),
    };
    let mut output = DataBlob {
        size: 0,
        data: core::ptr::null_mut(),
    };
    let description = ['P' as u16, 0];
    let ok = unsafe {
        CryptProtectData(
            &mut input,
            description.as_ptr(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            0,
            &mut output,
        )
    };
    input_bytes.fill(0);
    utf16.fill(0);
    if ok == 0 {
        return Err(last_error("DPAPI protection"));
    }
    let allocation = LocalAllocation {
        pointer: output.data,
        clear_len: output.size as usize,
    };
    if output.data.is_null() || output.size == 0 {
        return Err("DPAPI returned an empty credential blob".into());
    }
    let blob = unsafe { core::slice::from_raw_parts(output.data, output.size as usize) };
    let mut carrier = Vec::with_capacity(ACCOUNT_PREFIX.len() + blob.len());
    carrier.extend_from_slice(&ACCOUNT_PREFIX);
    carrier.extend_from_slice(blob);
    drop(allocation);
    if carrier.len() > MAX_CARRIER_BYTES {
        return Err("protected credential exceeds the native carrier bound".into());
    }
    Ok(STANDARD.encode(carrier))
}

#[cfg(not(windows))]
pub(crate) fn protect_account(_value: &str) -> Result<String, String> {
    Err("Windows account protection is only available on Windows".into())
}

#[cfg(windows)]
pub(crate) fn unprotect_account(carrier: &str) -> Result<String, String> {
    let mut decoded = STANDARD
        .decode(carrier)
        .map_err(|_| "account credential is not valid Base64")?;
    if decoded.len() > MAX_CARRIER_BYTES {
        return Err("account credential exceeds the native carrier bound".into());
    }
    if decoded.len() <= ACCOUNT_PREFIX.len() || decoded[..2] != ACCOUNT_PREFIX {
        return Err("account credential has the wrong protection header".into());
    }
    let mut input = DataBlob {
        size: u32::try_from(decoded.len() - 2).map_err(|_| "credential blob is too large")?,
        data: decoded[2..].as_mut_ptr(),
    };
    let mut output = DataBlob {
        size: 0,
        data: core::ptr::null_mut(),
    };
    let mut description = core::ptr::null_mut();
    let ok = unsafe {
        CryptUnprotectData(
            &mut input,
            &mut description,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            0,
            &mut output,
        )
    };
    decoded.fill(0);
    let description_allocation = LocalAllocation {
        pointer: description.cast(),
        clear_len: 0,
    };
    let output_allocation = LocalAllocation {
        pointer: output.data,
        clear_len: output.size as usize,
    };
    if ok == 0 {
        return Err(last_error("DPAPI unprotection"));
    }
    if output.data.is_null() || output.size < 2 || !output.size.is_multiple_of(2) {
        return Err("DPAPI returned malformed UTF-16 credential data".into());
    }
    let bytes = unsafe { core::slice::from_raw_parts(output.data, output.size as usize) };
    let mut units = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.as_chunks::<2>().0 {
        units.push(u16::from_le_bytes([pair[0], pair[1]]));
    }
    let result = (|| {
        let terminator = units
            .iter()
            .position(|unit| *unit == 0)
            .ok_or("DPAPI credential is missing its UTF-16 terminator")?;
        if terminator > MAX_PASSWORD_UTF16 {
            return Err("unprotected credential exceeds 256 UTF-16 code units".into());
        }
        String::from_utf16(&units[..terminator])
            .map_err(|_| "DPAPI credential contains invalid UTF-16".into())
    })();
    units.fill(0);
    drop(output_allocation);
    drop(description_allocation);
    result
}

#[cfg(not(windows))]
pub(crate) fn unprotect_account(_carrier: &str) -> Result<String, String> {
    Err("Windows account protection is only available on Windows".into())
}
