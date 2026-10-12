#![no_std]
#[allow(
    non_snake_case,
    non_camel_case_types,
    non_upper_case_globals,
    dead_code,
    unused_imports,
    unsafe_op_in_unsafe_fn,
    unnecessary_transmutes,
    clippy::all
)]
mod ffi {
    include!(concat!(env!("OUT_DIR"), "/wdk.rs"));
}
mod device;
mod state;
mod wfp;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    // SAFETY: A kernel panic cannot unwind across a driver callback.
    unsafe {
        ffi::KeBugCheckEx(0xE2, 0x50585253, 0, 0, 0);
    }
}

#[unsafe(export_name = "DriverEntry")]
/// # Safety
/// Invoked only by the Windows loader with a valid initialized DRIVER_OBJECT.
pub unsafe extern "system" fn driver_entry(
    driver: *mut ffi::DRIVER_OBJECT,
    _registry: *const ffi::UNICODE_STRING,
) -> i32 {
    if driver.is_null() {
        return 0xC000000Du32 as i32;
    }
    unsafe {
        state::initialize();
        device::initialize(driver)
    }
}
