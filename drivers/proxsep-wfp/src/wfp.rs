//! Connect redirection through documented WFP DDIs; no original binary code.
use crate::{ffi::*, state};
use core::{
    ffi::c_void,
    ptr::{null, null_mut},
    sync::atomic::{AtomicPtr, AtomicU32, Ordering},
};
use proxsep_wfp_policy::{MAX_APP_ID, should_capture};

pub static REDIRECT: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
static ENGINE: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
static CALLOUT_V4: AtomicU32 = AtomicU32::new(0);
static CALLOUT_V6: AtomicU32 = AtomicU32::new(0);

const fn guid(a: u32, b: u16, c: u16, d: [u8; 8]) -> GUID {
    GUID {
        Data1: a,
        Data2: b,
        Data3: c,
        Data4: d,
    }
}
pub const DEVICE_CLASS: GUID = guid(
    0x83604a23,
    0x58e4,
    0x4a5d,
    [0x82, 0x41, 0x12, 0xba, 0xd1, 0x5f, 0x54, 0xab],
);
const PROVIDER: GUID = guid(
    0x4cd391a9,
    0x350b,
    0x42e7,
    [0xa0, 0xa7, 0xd2, 0x26, 0xad, 0x41, 0x0a, 0x11],
);
const SUBLAYER: GUID = guid(
    0x919b8434,
    0x2b7c,
    0x4b27,
    [0x93, 0x0d, 0xe7, 0xab, 0x3e, 0x65, 0x1a, 0xc1],
);
const CALL_V4: GUID = guid(
    0x778f7c94,
    0x66ed,
    0x47a0,
    [0xae, 0x71, 0x65, 0xd9, 0x41, 0x92, 0x6d, 0x1b],
);
const CALL_V6: GUID = guid(
    0xad393670,
    0xe2d9,
    0x49be,
    [0x8b, 0x48, 0xd2, 0xd4, 0x41, 0xba, 0x45, 0x0f],
);
const LAYER_V4: GUID = guid(
    0xc6e63c8c,
    0xb784,
    0x4562,
    [0xaa, 0x7d, 0x0a, 0x67, 0xcf, 0xca, 0xf9, 0xa3],
);
const LAYER_V6: GUID = guid(
    0x587e54a7,
    0x8046,
    0x42ba,
    [0xa0, 0xaa, 0xb7, 0x16, 0x25, 0x0f, 0xc7, 0xfd],
);
const COND_PROTOCOL: GUID = guid(
    0x3971ef2b,
    0x623e,
    0x4f9a,
    [0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7],
);
const COND_REMOTE_PORT: GUID = guid(
    0xc35a604d,
    0xd22b,
    0x4e1a,
    [0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b],
);

pub const fn wide<const N: usize>(bytes: &[u8; N]) -> [u16; N] {
    let mut result = [0; N];
    let mut i = 0;
    while i < N {
        result[i] = bytes[i] as u16;
        i += 1;
    }
    result
}

pub unsafe fn initialize(device: *mut DEVICE_OBJECT) -> i32 {
    let mut redirect = null_mut();
    let status = unsafe { FwpsRedirectHandleCreate0(&PROVIDER, 0, &mut redirect) };
    if status < 0 {
        return status;
    }
    REDIRECT.store(redirect, Ordering::Release);
    for (key, id) in [(&CALL_V4, &CALLOUT_V4), (&CALL_V6, &CALLOUT_V6)] {
        let mut callout: FWPS_CALLOUT1 = unsafe { core::mem::zeroed() };
        callout.calloutKey = *key;
        callout.classifyFn = Some(classify);
        callout.notifyFn = Some(notify);
        let mut number = 0;
        let status = unsafe { FwpsCalloutRegister1(device.cast(), &callout, &mut number) };
        if status < 0 {
            unsafe {
                cleanup();
            }
            return status;
        }
        id.store(number, Ordering::Release);
    }
    let mut session: FWPM_SESSION0 = unsafe { core::mem::zeroed() };
    session.flags = 1;
    let mut engine = null_mut();
    let status = unsafe { FwpmEngineOpen0(null(), 10, null_mut(), &session, &mut engine) };
    if status < 0 {
        unsafe {
            cleanup();
        }
        return status;
    }
    ENGINE.store(engine, Ordering::Release);
    let status = unsafe { FwpmTransactionBegin0(engine, 0) };
    if status < 0 {
        unsafe {
            cleanup();
        }
        return status;
    }
    let name = wide(b"ProxSep connect redirection\0");
    let mut provider: FWPM_PROVIDER0 = unsafe { core::mem::zeroed() };
    provider.providerKey = PROVIDER;
    provider.displayData.name = name.as_ptr().cast_mut();
    let mut status = unsafe { FwpmProviderAdd0(engine, &provider, null_mut()) };
    if status >= 0 {
        let mut sublayer: FWPM_SUBLAYER0 = unsafe { core::mem::zeroed() };
        sublayer.subLayerKey = SUBLAYER;
        sublayer.providerKey = (&PROVIDER as *const GUID).cast_mut();
        sublayer.displayData.name = name.as_ptr().cast_mut();
        sublayer.weight = 0x800a;
        status = unsafe { FwpmSubLayerAdd0(engine, &sublayer, null_mut()) };
    }
    for (key, layer) in [(&CALL_V4, &LAYER_V4), (&CALL_V6, &LAYER_V6)] {
        if status < 0 {
            break;
        }
        let mut callout: FWPM_CALLOUT0 = unsafe { core::mem::zeroed() };
        callout.calloutKey = *key;
        callout.applicableLayer = *layer;
        callout.providerKey = (&PROVIDER as *const GUID).cast_mut();
        callout.displayData.name = name.as_ptr().cast_mut();
        status = unsafe { FwpmCalloutAdd0(engine, &callout, null_mut(), null_mut()) };
        for protocol in [6u8, 17u8] {
            if status < 0 {
                break;
            }
            let mut conditions: [FWPM_FILTER_CONDITION0; 2] = unsafe { core::mem::zeroed() };
            conditions[0].fieldKey = COND_PROTOCOL;
            conditions[0].matchType = 0;
            conditions[0].conditionValue.type_ = 1;
            conditions[0].conditionValue.__bindgen_anon_1.uint8 = protocol;
            conditions[1].fieldKey = COND_REMOTE_PORT;
            conditions[1].matchType = 10;
            conditions[1].conditionValue.type_ = 2;
            conditions[1].conditionValue.__bindgen_anon_1.uint16 = 53;
            let mut filter: FWPM_FILTER0 = unsafe { core::mem::zeroed() };
            filter.layerKey = *layer;
            filter.subLayerKey = SUBLAYER;
            filter.providerKey = (&PROVIDER as *const GUID).cast_mut();
            filter.displayData.name = name.as_ptr().cast_mut();
            filter.action.type_ = 0x5003;
            filter.action.__bindgen_anon_1.calloutKey = *key;
            filter.weight.type_ = 0;
            filter.numFilterConditions = if protocol == 6 { 1 } else { 2 };
            filter.filterCondition = conditions.as_mut_ptr();
            status = unsafe { FwpmFilterAdd0(engine, &filter, null_mut(), null_mut()) };
        }
    }
    if status >= 0 {
        status = unsafe { FwpmTransactionCommit0(engine) };
    }
    if status < 0 {
        unsafe {
            let _ = FwpmTransactionAbort0(engine);
            cleanup();
        }
    }
    status
}

pub unsafe fn cleanup() {
    let engine = ENGINE.swap(null_mut(), Ordering::AcqRel);
    if !engine.is_null() {
        unsafe {
            let _ = FwpmEngineClose0(engine);
        }
    }
    for id in [&CALLOUT_V4, &CALLOUT_V6] {
        let number = id.swap(0, Ordering::AcqRel);
        if number != 0 {
            unsafe {
                let _ = FwpsCalloutUnregisterById0(number);
            }
        }
    }
    let redirect = REDIRECT.swap(null_mut(), Ordering::AcqRel);
    if !redirect.is_null() {
        unsafe {
            FwpsRedirectHandleDestroy0(redirect);
        }
    }
}

unsafe extern "C" fn notify(
    _kind: FWPS_CALLOUT_NOTIFY_TYPE,
    _key: *const GUID,
    _filter: *mut FWPS_FILTER1,
) -> i32 {
    0
}

unsafe fn original_addresses(request: &FWPS_CONNECT_REQUEST0, event: &mut [u8; 304]) -> bool {
    // WFP supplies this full struct at connect-redirect layers for the callback
    // duration; copy before mutating. Preserve scope/flow, not merely address.
    let local = unsafe {
        core::slice::from_raw_parts(
            (&request.localAddressAndPort as *const SOCKADDR_STORAGE).cast::<u8>(),
            28,
        )
    };
    let remote = unsafe {
        core::slice::from_raw_parts(
            (&request.remoteAddressAndPort as *const SOCKADDR_STORAGE).cast::<u8>(),
            28,
        )
    };
    proxsep_wfp_policy::copy_original_addresses(event, local, remote).is_ok()
}

unsafe extern "C" fn classify(
    fixed: *const FWPS_INCOMING_VALUES0,
    metadata: *const FWPS_INCOMING_METADATA_VALUES0,
    layer: *mut c_void,
    context: *const c_void,
    filter: *const FWPS_FILTER1,
    _flow: u64,
    output: *mut FWPS_CLASSIFY_OUT0,
) {
    if output.is_null() {
        return;
    }
    let output = unsafe { &mut *output };
    if output.rights & 1 == 0 {
        return;
    }
    output.actionType = 0x1002;
    let Some(_rundown) = (unsafe { state::acquire() }) else {
        return;
    };
    if fixed.is_null()
        || metadata.is_null()
        || filter.is_null()
        || context.is_null()
        || layer.is_null()
    {
        return;
    }
    let fixed = unsafe { &*fixed };
    let metadata = unsafe { &*metadata };
    if fixed.layerId != 66 && fixed.layerId != 67
        || fixed.valueCount < 9
        || fixed.incomingValue.is_null()
    {
        return;
    }
    if metadata.currentMetadataValues & 0x20 == 0 || metadata.processId > u32::MAX as u64 {
        return;
    }
    let values =
        unsafe { core::slice::from_raw_parts(fixed.incomingValue, fixed.valueCount as usize) };
    let protocol = unsafe { values[5].value.__bindgen_anon_1.uint8 };
    let remote_port = unsafe { values[8].value.__bindgen_anon_1.uint16 };
    unsafe {
        state::sweep();
    }
    let (operation, automatic) = {
        let mut state = unsafe { state::lock() };
        if state.closing {
            return;
        }
        if !should_capture(
            state.gate.is_running(),
            metadata.processId as u32,
            state.proxy_pid,
            protocol,
            remote_port,
        ) {
            return;
        }
        if protocol == 17
            && (if state.capture_flags & 8 != 0 {
                remote_port != 443
            } else {
                state.capture_flags & 16 == 0
            })
        {
            return;
        }
        let automatic = if state.automatic {
            let mut listener = [0u8; 28];
            if fixed.layerId == 67 {
                listener = state.listener_v6;
            } else {
                listener[..16].copy_from_slice(&state.listener_v4);
            }
            if protocol != 6 || listener[2..4] == [0, 0] {
                return;
            }
            Some((state.proxy_pid, listener))
        } else {
            None
        };
        let Some(generation) = state.gate.enter() else {
            return;
        };
        (state::OperationGuard::new(generation), automatic)
    };
    let redirect = REDIRECT.load(Ordering::Acquire);
    if metadata.currentMetadataValues & 0x40000000 != 0
        && !metadata.redirectRecords.is_null()
        && unsafe {
            FwpsQueryConnectionRedirectState0(metadata.redirectRecords, redirect, null_mut())
        } != 0
    {
        return;
    }
    let app = unsafe { values[0].value.__bindgen_anon_1.byteBlob };
    let app_len = if app.is_null() {
        0
    } else {
        unsafe { (*app).size as usize }
    };
    if app_len > MAX_APP_ID || app_len != 0 && unsafe { (*app).data.is_null() } {
        unsafe {
            state::lock().dropped_events += 1;
        }
        return;
    }
    let mut event = [0u8; 304];
    event[..4].copy_from_slice(&304u32.to_le_bytes());
    event[24..28].copy_from_slice(&(app_len as u32).to_le_bytes());
    event[28..32].copy_from_slice(&(app_len as u32).to_le_bytes());
    event[32..36].copy_from_slice(&2u32.to_le_bytes());
    event[36..40].copy_from_slice(&(metadata.processId as u32).to_le_bytes());
    event[180..184].copy_from_slice(&(protocol as u32).to_le_bytes());
    if metadata.currentMetadataValues & 0x8000 != 0 {
        event[192..200].copy_from_slice(&metadata.transportEndpointHandle.to_le_bytes());
    }
    if !unsafe { original_addresses(&*layer.cast::<FWPS_CONNECT_REQUEST0>(), &mut event) } {
        return;
    }
    let mut handle = 0;
    if unsafe { FwpsAcquireClassifyHandle0(context.cast_mut(), 0, &mut handle) } < 0 {
        return;
    }
    if let Some((proxy_pid, listener)) = automatic {
        let mut writable = null_mut();
        let status = unsafe {
            FwpsAcquireWritableLayerDataPointer0(
                handle,
                (*filter).filterId,
                0,
                &mut writable,
                output,
            )
        };
        if status >= 0 && !writable.is_null() {
            let app_bytes = if app_len == 0 {
                &[]
            } else {
                unsafe { core::slice::from_raw_parts((*app).data, app_len) }
            };
            // STOP waits for operation through Apply and Release; a stale epoch
            // must not modify even if the controller has requested a new start.
            if unsafe { operation.may_modify() } {
                let request = unsafe { &mut *writable.cast::<FWPS_CONNECT_REQUEST0>() };
                if unsafe { modify_request(request, &event, app_bytes, &listener, proxy_pid) } < 0 {
                    unsafe {
                        state::lock().dropped_events += 1;
                    }
                }
            }
            unsafe {
                FwpsApplyModifiedLayerData0(handle, writable, 0);
            }
            output.actionType = 0x1002;
            output.rights |= 1;
        }
        unsafe {
            FwpsReleaseClassifyHandle0(handle);
        }
        return;
    }
    let mut state = unsafe { state::lock() };
    if !state.gate.may_modify(operation.generation) {
        drop(state);
        unsafe {
            FwpsReleaseClassifyHandle0(handle);
        }
        return;
    }
    let Some(index) = state
        .slots
        .iter()
        .position(|slot| slot.handle == 0 && !slot.reserved)
    else {
        state.dropped_events += 1;
        drop(state);
        unsafe {
            FwpsReleaseClassifyHandle0(handle);
        }
        return;
    };
    let saved_output = *output;
    let filter_id = unsafe { (*filter).filterId };
    state.slots[index].reserved = true;
    state.slots[index].generation = operation.generation;
    drop(state);
    let status = unsafe { FwpsPendClassify0(handle, filter_id, 0, output) };
    if status >= 0 {
        output.actionType = 0x1001;
        output.rights &= !1;
    }
    let mut state = unsafe { state::lock() };
    if status < 0 {
        state.slots[index].reserved = false;
        drop(state);
        unsafe {
            FwpsReleaseClassifyHandle0(handle);
        }
        return;
    }
    if !state.gate.may_modify(operation.generation) {
        state.slots[index].reserved = false;
        drop(state);
        unsafe {
            state::complete_permit(handle, saved_output);
        }
        return;
    }
    let created = unsafe { KeQueryUnbiasedInterruptTime() };
    event[184..192].copy_from_slice(&handle.to_le_bytes());
    event[208..216].copy_from_slice(&created.to_le_bytes());
    let slot = &mut state.slots[index];
    slot.handle = handle;
    slot.filter_id = filter_id;
    slot.created = created;
    slot.delivered = false;
    slot.app_len = app_len as u32;
    slot.event = event;
    slot.output = saved_output;
    if app_len != 0 {
        unsafe {
            core::ptr::copy_nonoverlapping((*app).data, slot.app.as_mut_ptr(), app_len);
        }
    }
}

pub unsafe fn respond(bytes: &[u8]) -> i32 {
    if bytes.len() != 304 {
        return 0xC0000206u32 as i32;
    }
    let handle = proxsep_wfp_policy::read_u64(bytes, 184);
    let mut app = [0u8; MAX_APP_ID];
    let (operation, filter_id, output, original, proxy_pid, app_len) = {
        let mut state = unsafe { state::lock() };
        let Some(index) = state
            .slots
            .iter()
            .position(|slot| slot.handle == handle && handle != 0)
        else {
            return 0xC0000151u32 as i32;
        };
        if !state.gate.may_modify(state.slots[index].generation) {
            return 0xC0000080u32 as i32;
        }
        let slot = &state.slots[index];
        let family = u16::from_le_bytes([slot.event[276], slot.event[277]]);
        if proxsep_wfp_policy::validate_response(bytes, family).is_err() {
            return 0xC000000Du32 as i32;
        }
        app[..slot.app_len as usize].copy_from_slice(&slot.app[..slot.app_len as usize]);
        let copied = (
            slot.filter_id,
            slot.output,
            slot.event,
            state.proxy_pid,
            slot.app_len as usize,
        );
        let Some(generation) = state.gate.enter() else {
            return 0xC000009Au32 as i32;
        };
        state.slots[index].handle = 0;
        state.slots[index].reserved = false;
        state.abandoned_batches = 0;
        (
            state::OperationGuard::new(generation),
            copied.0,
            copied.1,
            copied.2,
            copied.3,
            copied.4,
        )
    };
    let mut status = 0;
    if proxsep_wfp_policy::read_u32(bytes, 204) & 2 != 0 {
        let mut writable = null_mut();
        let mut writable_output = output;
        status = unsafe {
            FwpsAcquireWritableLayerDataPointer0(
                handle,
                filter_id,
                0,
                &mut writable,
                &mut writable_output,
            )
        };
        if status >= 0 && !writable.is_null() {
            let request = unsafe { &mut *writable.cast::<FWPS_CONNECT_REQUEST0>() };
            status = if unsafe { operation.may_modify() } {
                unsafe {
                    modify_request(
                        request,
                        &original,
                        &app[..app_len],
                        &bytes[276..304],
                        proxy_pid,
                    )
                }
            } else {
                0xC0000080u32 as i32
            };
            unsafe {
                FwpsApplyModifiedLayerData0(handle, writable, 0);
            }
        }
    }
    unsafe {
        state::complete_permit(handle, output);
    }
    status
}

/// WFP owns/frees this nonpaged allocation once ApplyModifiedLayerData runs.
unsafe fn modify_request(
    request: &mut FWPS_CONNECT_REQUEST0,
    event: &[u8; 304],
    app: &[u8],
    destination: &[u8],
    proxy_pid: u32,
) -> i32 {
    if request.localRedirectTargetPID != 0 {
        return 0xC000009Eu32 as i32;
    }
    let local = unsafe {
        core::slice::from_raw_parts(
            (&request.localAddressAndPort as *const SOCKADDR_STORAGE).cast::<u8>(),
            28,
        )
    };
    if !proxsep_wfp_policy::loopback_redirect_source_allowed(local) {
        return 0xC00000BBu32 as i32;
    }
    let context = unsafe { ExAllocatePool2(0x40, (304 + app.len()) as u64, 0x52585050) };
    if context.is_null() {
        return 0xC000009Au32 as i32;
    }
    unsafe {
        core::ptr::copy_nonoverlapping(event.as_ptr(), context.cast::<u8>(), 304);
        core::ptr::copy_nonoverlapping(app.as_ptr(), context.cast::<u8>().add(304), app.len());
    }
    request.localRedirectContext = context;
    request.localRedirectContextSize = (304 + app.len()) as u64;
    request.localRedirectTargetPID = proxy_pid;
    request.localRedirectHandle = REDIRECT.load(Ordering::Acquire);
    let length = if event[276..278] == 2u16.to_le_bytes() {
        16
    } else {
        28
    };
    unsafe {
        core::ptr::copy_nonoverlapping(
            destination.as_ptr(),
            (&mut request.remoteAddressAndPort as *mut SOCKADDR_STORAGE).cast::<u8>(),
            length,
        );
    }
    0
}
