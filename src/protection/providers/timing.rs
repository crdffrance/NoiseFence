//! Cancellation-safe phase accounting. No URLs, credentials or response data.
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Instant,
};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Cache,
    Capacity,
    Storage,
    ResponseHeaders,
    ResponseBody,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TimingReport {
    pub budget_ms: u64,
    pub deadline_exceeded: bool,
    pub phase_ms: BTreeMap<Phase, u64>,
    pub cancelled: BTreeMap<Phase, usize>,
}

#[derive(Default)]
struct State {
    next: u64,
    active: BTreeMap<u64, (Phase, Instant)>,
    totals_us: BTreeMap<Phase, u64>,
    cancelled: BTreeMap<Phase, usize>,
}
#[derive(Default, Clone)]
pub(super) struct Timings(Arc<Mutex<State>>);
pub(super) struct Span {
    timings: Timings,
    id: u64,
}
impl Timings {
    pub fn start(&self, phase: Phase) -> Span {
        let mut state = self.0.lock().unwrap();
        let id = state.next;
        state.next += 1;
        state.active.insert(id, (phase, Instant::now()));
        Span {
            timings: self.clone(),
            id,
        }
    }
    pub fn report(&self, budget_ms: u64, deadline_exceeded: bool) -> TimingReport {
        let state = self.0.lock().unwrap();
        let mut totals = state.totals_us.clone();
        let mut cancelled = state.cancelled.clone();
        // JoinSet cancellation may not have dropped every spawned future yet.
        // Snapshot outstanding phases without depending on scheduler ordering.
        for &(phase, started) in state.active.values() {
            *totals.entry(phase).or_default() += started.elapsed().as_micros() as u64;
            if deadline_exceeded {
                *cancelled.entry(phase).or_default() += 1;
            }
        }
        TimingReport {
            budget_ms,
            deadline_exceeded,
            phase_ms: totals.into_iter().map(|(p, us)| (p, us / 1000)).collect(),
            cancelled,
        }
    }
}
impl Span {
    pub fn finish(self) {
        self.record(false);
    }
    fn record(&self, cancelled: bool) {
        let mut state = self.timings.0.lock().unwrap();
        if let Some((phase, started)) = state.active.remove(&self.id) {
            *state.totals_us.entry(phase).or_default() += started.elapsed().as_micros() as u64;
            if cancelled {
                *state.cancelled.entry(phase).or_default() += 1;
            }
        }
    }
}
impl Drop for Span {
    fn drop(&mut self) {
        self.record(true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn completed_cancelled_and_pending_spans_are_distinct() {
        let timings = Timings::default();
        timings.start(Phase::Cache).finish();
        drop(timings.start(Phase::ResponseHeaders));
        let pending = timings.start(Phase::Capacity);
        let report = timings.report(1200, true);
        assert_eq!(report.cancelled.len(), 2);
        assert_eq!(report.cancelled[&Phase::ResponseHeaders], 1);
        assert_eq!(report.cancelled[&Phase::Capacity], 1);
        drop(pending);
        assert_eq!(timings.report(1200, true).cancelled, report.cancelled);
        let json = serde_json::to_value(report).unwrap();
        assert!(json["phase_ms"]["response_headers"].is_number());
    }
}
