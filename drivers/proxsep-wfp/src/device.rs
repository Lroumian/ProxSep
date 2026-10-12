//! Buffered device control. Polls complete immediately; no pended IRPs.
use crate::{ffi::*, state, wfp};
use core::{
    ptr::null_mut,
    sync::atomic::{AtomicPtr, Ordering},
};
use proxsep_wfp_policy::{read_u32, validate_config};

static DEVICE: AtomicPtr<DEVICE_OBJECT> = AtomicPtr::new(null_mut());

pub fn unicode(bytes: &mut [u16]) -> UNICODE_STRING {
    UNICODE_STRING {
        Length: ((bytes.len() - 1) * 2) as u16,
        MaximumLength: (bytes.len() * 2) as u16,
        Buffer: bytes.as_mut_ptr(),
    }
}

pub unsafe fn initialize(driver: *mut DRIVER_OBJECT) -> i32 {
    let mut name = wfp::wide(b"\\Device\\ProxSepDrv\0");
    let mut link = wfp::wide(b"\\DosDevices\\Global\\ProxSepDrv\0");
    let mut sddl = wfp::wide(b"D:P(A;;GA;;;SY)(A;;GA;;;BA)\0");
    let mut name = unicode(&mut name);
    let mut link = unicode(&mut link);
    let sddl = unicode(&mut sddl);
    let mut device = null_mut();
    let status = unsafe {
        WdmlibIoCreateDeviceSecure(
            driver,
            0,
            &mut name,
            0x12,
            0x100,
            0,
            &sddl,
            &wfp::DEVICE_CLASS,
            &mut device,
        )
    };
    if status < 0 {
        return status;
    }
    DEVICE.store(device, Ordering::Release);
    unsafe {
        (*driver).MajorFunction.fill(Some(dispatch_request));
        (*driver).DriverUnload = Some(unload);
        (*device).Flags |= 4;
    }
    let status = unsafe { IoCreateSymbolicLink(&mut link, &mut name) };
    if status < 0 {
        unsafe {
            cleanup();
        }
        return status;
    }
    let status = unsafe { wfp::initialize(device) };
    if status < 0 {
        unsafe {
            cleanup();
        }
        return status;
    }
    unsafe {
        (*device).Flags &= !0x80;
    }
    0
}

pub unsafe fn cleanup() {
    let mut link = wfp::wide(b"\\DosDevices\\Global\\ProxSepDrv\0");
    unsafe {
        let _ = IoDeleteSymbolicLink(&mut unicode(&mut link));
    }
    let device = DEVICE.swap(null_mut(), Ordering::AcqRel);
    if !device.is_null() {
        unsafe {
            IoDeleteDevice(device);
        }
    }
}

unsafe extern "C" fn unload(_driver: *mut DRIVER_OBJECT) {
    unsafe {
        state::wait_for_rundown();
        let _ = state::stop();
        wfp::cleanup();
        cleanup();
    }
}

unsafe fn finish(irp: *mut IRP, status: i32, information: usize) -> i32 {
    unsafe {
        (*irp).IoStatus.__bindgen_anon_1.Status = status;
        (*irp).IoStatus.Information = information as u64;
        IofCompleteRequest(irp, 0);
    }
    status
}

unsafe extern "C" fn dispatch_request(_device: *mut DEVICE_OBJECT, irp: *mut IRP) -> i32 {
    if irp.is_null() {
        return 0xC000000Du32 as i32;
    }
    let Some(_rundown) = (unsafe { state::acquire() }) else {
        return unsafe { finish(irp, 0xC0000056u32 as i32, 0) };
    };
    let stack = unsafe {
        (*irp)
            .Tail
            .Overlay
            .__bindgen_anon_2
            .__bindgen_anon_1
            .CurrentStackLocation
    };
    if stack.is_null() {
        return unsafe { finish(irp, 0xC000000Du32 as i32, 0) };
    }
    let stack = unsafe { &*stack };
    let file = stack.FileObject as usize;
    let mut status = 0;
    let mut information = 0;
    match stack.MajorFunction {
        0 => {
            let mut state = unsafe { state::lock() };
            if state.owner_file != 0 {
                status = 0xC0000043u32 as i32;
            } else {
                let pid = unsafe { PsGetCurrentProcessId() } as usize;
                if pid == 0 || pid > u32::MAX as usize {
                    status = 0xC0000022u32 as i32;
                } else {
                    state.owner_file = file;
                    state.owner_pid = pid as u32;
                    state.closing = false;
                    state.configured = false;
                }
            }
        }
        2 | 18 => {
            let owned = {
                let mut state = unsafe { state::lock() };
                let owned = state.owner_file == file;
                if owned {
                    state.closing = true;
                    state.configured = false;
                }
                owned
            };
            if owned {
                unsafe {
                    status = state::stop();
                }
                let mut state = unsafe { state::lock() };
                state.configured = false;
                if stack.MajorFunction == 2 {
                    state.owner_file = 0;
                    state.owner_pid = 0;
                }
            }
        }
        14 => {
            let owner_pid = {
                let state = unsafe { state::lock() };
                if state.closing
                    || state.owner_file != file
                    || state.owner_pid as usize != unsafe { PsGetCurrentProcessId() } as usize
                {
                    0
                } else {
                    state.owner_pid
                }
            };
            if owner_pid == 0 {
                status = 0xC0000022u32 as i32;
            } else {
                let parameters = unsafe { stack.Parameters.DeviceIoControl };
                let input_len = parameters.InputBufferLength as usize;
                let output_len = parameters.OutputBufferLength as usize;
                let buffer = unsafe { (*irp).AssociatedIrp.SystemBuffer }.cast::<u8>();
                if buffer.is_null() && (input_len != 0 || output_len != 0) {
                    status = 0xC000000Du32 as i32;
                } else {
                    let result = unsafe {
                        control(
                            parameters.IoControlCode,
                            buffer,
                            input_len,
                            output_len,
                            owner_pid,
                        )
                    };
                    status = result.0;
                    information = result.1;
                }
            }
        }
        _ => status = 0xC0000010u32 as i32,
    }
    unsafe { finish(irp, status, information) }
}

unsafe fn control(
    code: u32,
    buffer: *mut u8,
    input_len: usize,
    output_len: usize,
    owner_pid: u32,
) -> (i32, usize) {
    match code {
        0x120004 => {
            let mut state = unsafe { state::lock() };
            if state.closing || state.owner_pid != owner_pid || !state.configured {
                (0xC0000182u32 as i32, 0)
            } else if state.gate.is_running() {
                (0xC0000718u32 as i32, 0)
            } else {
                if state.gate.start() {
                    (0, 0)
                } else {
                    (0xC000009Eu32 as i32, 0)
                }
            }
        }
        0x120008 => {
            if unsafe { state::lock().gate.is_stopped() } {
                (0xC0000080u32 as i32, 0)
            } else {
                (unsafe { state::stop() }, 0)
            }
        }
        0x12000C => {
            if output_len < 4 {
                (0xC0000023u32 as i32, 4)
            } else {
                unsafe {
                    core::ptr::copy_nonoverlapping(120u32.to_le_bytes().as_ptr(), buffer, 4);
                }
                (0, 4)
            }
        }
        0x120010 => {
            if input_len != 51_256 {
                return (0xC0000206u32 as i32, 0);
            }
            let input = unsafe { core::slice::from_raw_parts(buffer, input_len) };
            if validate_config(input, owner_pid).is_err() {
                return (0xC000000Du32 as i32, 0);
            }
            let mut state = unsafe { state::lock() };
            if state.closing || state.owner_pid != owner_pid || !state.gate.can_configure() {
                return (0xC000009Eu32 as i32, 0);
            }
            state.proxy_pid = owner_pid;
            state.capture_flags = read_u32(input, 8);
            state.configured = true;
            state.automatic = false;
            (0, 0)
        }
        0x12E004 => {
            if input_len != 64 {
                return (0xC0000206u32 as i32, 0);
            }
            let input = unsafe { core::slice::from_raw_parts(buffer, 64) };
            if proxsep_wfp_policy::validate_independent_config(input, owner_pid).is_err() {
                return (0xC000000Du32 as i32, 0);
            }
            let mut state = unsafe { state::lock() };
            if state.closing || state.owner_pid != owner_pid || !state.gate.can_configure() {
                return (0xC000009Eu32 as i32, 0);
            }
            state.proxy_pid = owner_pid;
            state.capture_flags = 0;
            state.automatic = true;
            state.configured = true;
            state.listener_v4.copy_from_slice(&input[20..36]);
            state.listener_v6.copy_from_slice(&input[36..64]);
            (0, 0)
        }
        0x120014 => {
            unsafe {
                state::sweep();
            }
            let mut state = unsafe { state::lock() };
            let Some(index) = state
                .slots
                .iter()
                .enumerate()
                .filter(|(_, slot)| slot.handle != 0 && !slot.delivered)
                .min_by_key(|(_, slot)| slot.created)
                .map(|(index, _)| index)
            else {
                return (0x8000001Au32 as i32, 0);
            };
            let slot = &mut state.slots[index];
            let required = 304 + slot.app_len as usize;
            if output_len < required {
                return (0xC0000023u32 as i32, required);
            }
            unsafe {
                core::ptr::copy_nonoverlapping(slot.event.as_ptr(), buffer, 304);
                core::ptr::copy_nonoverlapping(
                    slot.app.as_ptr(),
                    buffer.add(304),
                    slot.app_len as usize,
                );
            }
            slot.delivered = true;
            (0, required)
        }
        0x12001C => {
            if !unsafe { state::lock().gate.is_running() } {
                return (0xC0000080u32 as i32, 0);
            }
            if input_len != 304 {
                return (0xC0000206u32 as i32, 0);
            }
            let response = unsafe { core::slice::from_raw_parts(buffer, 304) };
            (unsafe { wfp::respond(response) }, 0)
        }
        0x120020 => {
            if output_len < 12 {
                return (0xC0000023u32 as i32, 12);
            }
            let count = unsafe {
                state::lock()
                    .slots
                    .iter()
                    .filter(|slot| slot.handle != 0)
                    .count() as u32
            };
            let mut counters = [0u8; 12];
            counters[..4].copy_from_slice(&12u32.to_le_bytes());
            counters[8..12].copy_from_slice(&count.to_le_bytes());
            unsafe {
                core::ptr::copy_nonoverlapping(counters.as_ptr(), buffer, 12);
            }
            (0, 12)
        }
        // DNS transport injection and stream operations are not implemented.
        0x120018 | 0x120024 => (0xC0000002u32 as i32, 0),
        _ => (0xC000000Du32 as i32, 0),
    }
}
