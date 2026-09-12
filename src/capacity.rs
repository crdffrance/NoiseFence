//! Shared admission counter. Configuration revisions never multiply worker capacity.
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Debug)]
pub(crate) struct Capacity {
    active: AtomicUsize,
    limit: AtomicUsize,
    changed: tokio::sync::Notify,
}
#[derive(Debug)]
pub(crate) struct Permit(Arc<Capacity>);
impl Capacity {
    pub fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            active: AtomicUsize::new(0),
            limit: AtomicUsize::new(limit),
            changed: tokio::sync::Notify::new(),
        })
    }
    pub fn set_limit(&self, limit: usize) {
        self.limit.store(limit, Ordering::SeqCst);
        self.changed.notify_waiters();
    }
    pub fn try_acquire(self: &Arc<Self>) -> Result<Permit, ()> {
        let mut active = self.active.load(Ordering::SeqCst);
        loop {
            if active >= self.limit.load(Ordering::SeqCst) {
                return Err(());
            }
            match self.active.compare_exchange(
                active,
                active + 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return Ok(Permit(self.clone())),
                Err(current) => active = current,
            }
        }
    }
    pub async fn acquire(self: &Arc<Self>) -> Result<Permit, ()> {
        self.clone().acquire_owned().await
    }
    pub async fn acquire_owned(self: Arc<Self>) -> Result<Permit, ()> {
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Ok(p) = self.try_acquire() {
                return Ok(p);
            }
            notified.await;
        }
    }
    #[cfg(test)]
    pub fn available_permits(&self) -> usize {
        self.limit
            .load(Ordering::SeqCst)
            .saturating_sub(self.active.load(Ordering::SeqCst))
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
        self.0.changed.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn revisions_share_inflight_work_and_lower_limits_without_releasing_it() {
        let capacity = Capacity::new(2);
        let a = capacity.try_acquire().unwrap();
        let b = capacity.try_acquire().unwrap();
        capacity.set_limit(1);
        assert!(capacity.try_acquire().is_err());
        drop(a);
        assert!(capacity.try_acquire().is_err());
        let wait = tokio::spawn(capacity.clone().acquire_owned());
        tokio::task::yield_now().await;
        assert!(!wait.is_finished());
        drop(b);
        let permit = tokio::time::timeout(std::time::Duration::from_secs(1), wait)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(capacity.try_acquire().is_err());
        drop(permit);
        assert_eq!(capacity.available_permits(), 1);
        let permit = capacity.try_acquire().unwrap();
        let wait = tokio::spawn(capacity.clone().acquire_owned());
        tokio::task::yield_now().await;
        capacity.set_limit(2);
        let next = tokio::time::timeout(std::time::Duration::from_secs(1), wait)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        drop((permit, next));
        assert_eq!(capacity.available_permits(), 2);
    }
}
