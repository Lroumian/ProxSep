//! Spinlock-protected bounded ownership of pended WFP classifications.
use crate::ffi::*;
use core::{
    cell::UnsafeCell,
    marker::PhantomData,
    ops::{Deref, DerefMut},
};
use proxsep_wfp_policy::{EVENT_SIZE, EpochGate, MAX_APP_ID, MAX_PENDING};

#[derive(Clone, Copy)]
pub struct Slot {
    pub reserved: bool,
    pub generation: u64,
    pub handle: u64,
    pub filter_id: u64,
    pub created: u64,
    pub delivered: bool,
    pub app_len: u32,
    pub event: [u8; EVENT_SIZE],
    pub app: [u8; MAX_APP_ID],
    pub output: FWPS_CLASSIFY_OUT0,
}

pub struct State {
    pub gate: EpochGate,
    pub configured: bool,
    pub automatic: bool,
    pub listener_v4: [u8; 16],
    pub listener_v6: [u8; 28],
    pub proxy_pid: u32,
    pub capture_flags: u32,
    pub owner_file: usize,
    pub owner_pid: u32,
    pub closing: bool,
    pub abandoned_batches: u32,
    pub dropped_events: u64,
    pub slots: [Slot; MAX_PENDING],
}

struct Shared<T>(UnsafeCell<T>);
// SAFETY: All access to State is protected by LOCK. Rundown operations are
// atomic WDK DDIs; initialization occurs before device/callout publication.
unsafe impl<T> Sync for Shared<T> {}
static STATE: Shared<State> = Shared(UnsafeCell::new(unsafe { core::mem::zeroed() }));
static LOCK: Shared<KSPIN_LOCK> = Shared(UnsafeCell::new(0));
static RUNDOWN: Shared<EX_RUNDOWN_REF> = Shared(UnsafeCell::new(unsafe { core::mem::zeroed() }));
static STOPPED: Shared<KEVENT> = Shared(UnsafeCell::new(unsafe { core::mem::zeroed() }));

pub unsafe fn initialize() {
    unsafe {
        KeInitializeSpinLock(LOCK.0.get());
        ExInitializeRundownProtection(RUNDOWN.0.get());
        KeInitializeEvent(STOPPED.0.get(), 0, 1);
    }
}

pub struct StateGuard {
    old_irql: KIRQL,
    no_send: PhantomData<*mut ()>,
}
impl Deref for StateGuard {
    type Target = State;
    fn deref(&self) -> &State {
        unsafe { &*STATE.0.get() }
    }
}
impl DerefMut for StateGuard {
    fn deref_mut(&mut self) -> &mut State {
        unsafe { &mut *STATE.0.get() }
    }
}
impl Drop for StateGuard {
    fn drop(&mut self) {
        unsafe {
            KeReleaseSpinLock(LOCK.0.get(), self.old_irql);
        }
    }
}

pub unsafe fn lock() -> StateGuard {
    StateGuard {
        old_irql: unsafe { KeAcquireSpinLockRaiseToDpc(LOCK.0.get()) },
        no_send: PhantomData,
    }
}

pub struct RundownGuard;
impl Drop for RundownGuard {
    fn drop(&mut self) {
        unsafe {
            ExReleaseRundownProtection(RUNDOWN.0.get());
        }
    }
}
pub unsafe fn acquire() -> Option<RundownGuard> {
    if unsafe { ExAcquireRundownProtection(RUNDOWN.0.get()) } != 0 {
        Some(RundownGuard)
    } else {
        None
    }
}
pub unsafe fn wait_for_rundown() {
    unsafe {
        ExWaitForRundownProtectionRelease(RUNDOWN.0.get());
    }
}

pub unsafe fn complete_permit(handle: u64, mut output: FWPS_CLASSIFY_OUT0) {
    output.actionType = 0x1002;
    output.rights |= 1;
    unsafe {
        FwpsCompleteClassify0(handle, 0, &output);
        FwpsReleaseClassifyHandle0(handle);
    }
}

/// Owns every WFP operation until its final Apply/Complete/Release; notably
/// survives detaching a response from the pending table. Not Send.
pub struct OperationGuard {
    pub generation: u64,
    no_send: PhantomData<*mut ()>,
}
impl OperationGuard {
    pub fn new(generation: u64) -> Self {
        Self {
            generation,
            no_send: PhantomData,
        }
    }
    pub unsafe fn may_modify(&self) -> bool {
        unsafe { lock().gate.may_modify(self.generation) }
    }
}
impl Drop for OperationGuard {
    fn drop(&mut self) {
        let mut state = unsafe { lock() };
        let owned = state.gate.leave();
        debug_assert!(owned);
        if state.gate.is_stopped() {
            unsafe {
                KeSetEvent(STOPPED.0.get(), 0, 0);
            }
        }
    }
}

/// May run at DISPATCH_LEVEL. Only the first stopper drains the pending table.
/// No WFP DDI is called under LOCK. Later stoppers may join the stopped event.
pub unsafe fn request_stop(expected_generation: Option<u64>) {
    {
        let mut state = unsafe { lock() };
        if expected_generation.is_some_and(|g| !state.gate.may_modify(g))
            || !state.gate.begin_stop()
        {
            return;
        }
        unsafe {
            KeClearEvent(STOPPED.0.get());
        }
    }
    loop {
        let next = {
            let mut state = unsafe { lock() };
            if let Some(index) = state.slots.iter().position(|slot| slot.handle != 0) {
                let Some(generation) = state.gate.enter_completion() else {
                    break;
                };
                let slot = &mut state.slots[index];
                let next = (slot.handle, slot.output, OperationGuard::new(generation));
                slot.handle = 0;
                slot.reserved = false;
                Some(next)
            } else {
                None
            }
        };
        match next {
            Some((handle, output, _operation)) => unsafe {
                complete_permit(handle, output);
            },
            None => break,
        }
    }
    let mut state = unsafe { lock() };
    state.gate.mark_drained();
    if state.gate.is_stopped() {
        unsafe {
            KeSetEvent(STOPPED.0.get(), 0, 0);
        }
    }
}

/// Device STOP/CLEANUP/UNLOAD runs at PASSIVE_LEVEL. Do not block a WFP callback.
pub unsafe fn stop() -> i32 {
    if unsafe { KeGetCurrentIrql() } > 1 {
        return 0xC0000184u32 as i32;
    }
    unsafe {
        request_stop(None);
    }
    unsafe { KeWaitForSingleObject(STOPPED.0.get().cast(), 0, 0, 0, core::ptr::null_mut()) }
}

/// Expiry runs during callbacks and polls. There is no timer/DPC in this pass.
pub unsafe fn sweep() {
    let now = unsafe { KeQueryUnbiasedInterruptTime() };
    let generation = {
        let state = unsafe { lock() };
        if !state.gate.is_running() {
            return;
        }
        state.gate.generation()
    };
    let mut abandoned = false;
    loop {
        let next = {
            let mut state = unsafe { lock() };
            if !state.gate.may_modify(generation) {
                break;
            }
            if let Some(index) = state.slots.iter().position(|slot| {
                slot.handle != 0
                    && slot.generation == generation
                    && proxsep_wfp_policy::expired(now, slot.created)
            }) {
                let Some(completion_generation) = state.gate.enter_completion() else {
                    break;
                };
                let slot = &mut state.slots[index];
                let next = (
                    slot.handle,
                    slot.output,
                    OperationGuard::new(completion_generation),
                );
                slot.handle = 0;
                slot.reserved = false;
                Some(next)
            } else {
                None
            }
        };
        match next {
            Some((handle, output, _operation)) => {
                abandoned = true;
                unsafe {
                    complete_permit(handle, output);
                }
            }
            None => break,
        }
    }
    if abandoned {
        let emergency = {
            let mut state = unsafe { lock() };
            if !state.gate.may_modify(generation) {
                return;
            }
            state.abandoned_batches += 1;
            if state.abandoned_batches > 2 {
                state.abandoned_batches = 0;
                true
            } else {
                false
            }
        };
        if emergency {
            unsafe {
                request_stop(Some(generation));
            }
        }
    }
}
