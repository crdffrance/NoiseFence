//! Admission barrier. A preparation acknowledgement requires a drained fence;
//! dropping/cancelling its waiter does not reopen admission. Queue delivery is
//! independent: leases cover acceptance only, not already accepted mail.
use super::Epoch;
use anyhow::{Result, ensure};
use std::sync::{Arc, Mutex, Weak};
use tokio::sync::Notify;

struct State {
    active: Option<Epoch>,
    fence: Option<Epoch>,
    closed: bool,
    accepting: usize,
}
pub struct Gate {
    state: Mutex<State>,
    changed: Notify,
}
pub struct Acceptance {
    gate: Arc<Gate>,
}
/// Not serializable or constructible from a peer request.
pub struct Drained {
    gate: Weak<Gate>,
    fence: Epoch,
}

impl Gate {
    pub fn legacy() -> Arc<Self> {
        Self::new(None, false)
    }
    /// Recovery always starts closed, even if the last journal phase was released.
    /// The driver must load/validate the exact committed runtime before reopening.
    pub fn recovering(active: Option<Epoch>) -> Result<Arc<Self>> {
        if let Some(epoch) = &active {
            epoch.validate()?;
        }
        Ok(Self::new(active, true))
    }
    fn new(active: Option<Epoch>, closed: bool) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                active,
                fence: None,
                closed,
                accepting: 0,
            }),
            changed: Notify::new(),
        })
    }
    pub fn ready(&self) -> bool {
        !self.state.lock().unwrap().closed
    }
    pub fn epoch(&self) -> Option<Epoch> {
        self.state.lock().unwrap().active.clone()
    }
    pub fn enter(self: &Arc<Self>, expected: Option<&Epoch>) -> Result<Acceptance> {
        let mut state = self.state.lock().unwrap();
        ensure!(
            !state.closed && state.active.as_ref() == expected,
            "Activation in progress or SMTP policy changed; retry"
        );
        state.accepting = state
            .accepting
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("Too many acceptance leases"))?;
        Ok(Acceptance { gate: self.clone() })
    }
    pub async fn drain(self: &Arc<Self>, target: &Epoch) -> Result<Drained> {
        target.validate()?;
        {
            let mut state = self.state.lock().unwrap();
            if let Some(previous) = &state.fence {
                ensure!(
                    target.sequence > previous.sequence || (target == previous && state.closed),
                    "Stale or conflicting activation fence"
                );
            }
            ensure!(
                state.active.as_ref().is_none_or(|active| target == active
                    || (target.sequence > active.sequence && target.revision > active.revision)),
                "Fence predates or conflicts with loaded runtime"
            );
            state.closed = true;
            state.fence = Some(target.clone());
        }
        self.changed.notify_waiters();
        loop {
            // Register before inspecting state; lease release cannot be missed.
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let state = self.state.lock().unwrap();
                ensure!(
                    state.closed && state.fence.as_ref() == Some(target),
                    "Activation fence superseded"
                );
                if state.accepting == 0 {
                    return Ok(Drained {
                        gate: Arc::downgrade(self),
                        fence: target.clone(),
                    });
                }
            }
            notified.await;
        }
    }
    /// Enroll a running legacy snapshot only after its acceptances drained. The
    /// controller verifies/pins this bundle before binding it; this does not open
    /// admission or assert that any candidate model is prepared.
    pub fn bind_initial(self: &Arc<Self>, proof: &Drained, installed: &Epoch) -> Result<()> {
        installed.validate()?;
        ensure!(
            proof.gate.upgrade().is_some_and(|g| Arc::ptr_eq(&g, self)),
            "Foreign drain proof"
        );
        let mut state = self.state.lock().unwrap();
        ensure!(
            state.closed
                && state.accepting == 0
                && state.fence.as_ref() == Some(&proof.fence)
                && state.active.is_none()
                && installed.sequence < proof.fence.sequence
                && installed.revision < proof.fence.revision,
            "Initial snapshot cannot be bound"
        );
        state.active = Some(installed.clone());
        Ok(())
    }
    /// Driver persists release/abort and installs the verified runtime FIRST.
    /// Epoch may be the target (commit) or prior active epoch (pre-commit abort).
    pub fn resume(self: &Arc<Self>, proof: &Drained, installed: &Epoch) -> Result<()> {
        installed.validate()?;
        ensure!(
            proof.gate.upgrade().is_some_and(|g| Arc::ptr_eq(&g, self)),
            "Foreign drain proof"
        );
        let mut state = self.state.lock().unwrap();
        ensure!(
            state.fence.as_ref() == Some(&proof.fence),
            "Stale drain proof"
        );
        ensure!(
            *installed == proof.fence || state.active.as_ref() == Some(installed),
            "Unprepared runtime cannot resume admission"
        );
        if !state.closed {
            ensure!(
                state.active.as_ref() == Some(installed),
                "Release replay changed the runtime"
            );
            return Ok(());
        }
        ensure!(state.accepting == 0, "Acceptance still running");
        state.active = Some(installed.clone());
        state.closed = false;
        self.changed.notify_waiters();
        Ok(())
    }
}
impl Drop for Acceptance {
    fn drop(&mut self) {
        let mut state = self.gate.state.lock().unwrap();
        state.accepting -= 1;
        if state.accepting == 0 {
            self.gate.changed.notify_waiters();
        }
    }
}
