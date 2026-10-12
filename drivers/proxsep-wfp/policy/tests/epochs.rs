//! DDI-free barrier integration tests use the exact gate wired into kernel
//! callback/response ownership, not a separately implemented lifetime model.
use proxsep_wfp_policy::EpochGate;
use std::sync::{Arc, Barrier, Mutex};

#[test]
fn delayed_callback_cannot_publish_or_modify_after_stop_then_restart() {
    let gate = Arc::new(Mutex::new(EpochGate::default()));
    gate.lock().unwrap().start();
    let snapshot = Arc::new(Barrier::new(2));
    let resume = Arc::new(Barrier::new(2));
    let thread = std::thread::spawn({
        let gate = gate.clone();
        let snapshot = snapshot.clone();
        let resume = resume.clone();
        move || {
            let epoch = gate.lock().unwrap().enter().unwrap();
            snapshot.wait();
            resume.wait();
            assert!(!gate.lock().unwrap().may_modify(epoch));
            gate.lock().unwrap().leave();
            epoch
        }
    });
    snapshot.wait();
    {
        let mut state = gate.lock().unwrap();
        state.begin_stop();
        state.mark_drained();
        assert!(!state.is_stopped());
        assert!(!state.can_configure());
        assert!(!state.start());
    }
    resume.wait();
    let old = thread.join().unwrap();
    let mut state = gate.lock().unwrap();
    assert!(state.is_stopped());
    assert!(state.can_configure());
    assert!(state.start());
    assert!(!state.may_modify(old));
}

#[test]
fn detached_response_must_complete_release_once_before_stop_finishes() {
    let gate = Arc::new(Mutex::new(EpochGate::default()));
    gate.lock().unwrap().start();
    let detached = Arc::new(Barrier::new(2));
    let resume = Arc::new(Barrier::new(2));
    let counts = Arc::new(Mutex::new((0usize, 0usize, 0usize)));
    let thread = std::thread::spawn({
        let gate = gate.clone();
        let detached = detached.clone();
        let resume = resume.clone();
        let counts = counts.clone();
        move || {
            // Mirrors response token acquisition before slot.handle becomes zero.
            let epoch = gate.lock().unwrap().enter().unwrap();
            detached.wait();
            resume.wait();
            if gate.lock().unwrap().may_modify(epoch) {
                counts.lock().unwrap().0 += 1;
            }
            // Mock FwpsCompleteClassify / FwpsReleaseClassifyHandle.
            {
                let mut counts = counts.lock().unwrap();
                counts.1 += 1;
                counts.2 += 1;
            }
            gate.lock().unwrap().leave();
        }
    });
    detached.wait();
    {
        let mut state = gate.lock().unwrap();
        state.begin_stop();
        state.mark_drained();
        assert!(!state.is_stopped());
        assert!(!state.start());
    }
    resume.wait();
    thread.join().unwrap();
    assert!(gate.lock().unwrap().is_stopped());
    assert_eq!(*counts.lock().unwrap(), (0, 1, 1));
}
