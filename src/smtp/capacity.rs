use std::{sync::Arc, time::Duration};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Waiters are bounded by the SMTP connection limits. Tokio's semaphore queues
/// them in acquisition order, and dropping a timed-out/cancelled acquisition
/// removes its reservation. Hold the permit through DATA and durable enqueue.
pub(super) async fn acquire(slots: Arc<Semaphore>, wait_ms: u64) -> Option<OwnedSemaphorePermit> {
    if wait_ms == 0 {
        return slots.try_acquire_owned().ok();
    }
    tokio::time::timeout(Duration::from_millis(wait_ms), slots.acquire_owned())
        .await
        .ok()?
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Poll, Waker},
    };

    fn poll<T>(future: Pin<&mut impl Future<Output = T>>) -> Poll<T> {
        future.poll(&mut Context::from_waker(Waker::noop()))
    }

    #[tokio::test]
    async fn zero_wait_keeps_immediate_refusal_and_releases_on_drop() {
        let slots = Arc::new(Semaphore::new(1));
        let permit = acquire(slots.clone(), 0).await.unwrap();
        assert!(acquire(slots.clone(), 0).await.is_none());
        drop(permit);
        assert_eq!(slots.available_permits(), 1);
        slots.close();
        assert!(acquire(slots.clone(), 0).await.is_none());
        assert!(acquire(slots, 1000).await.is_none());
    }

    #[tokio::test]
    async fn earlier_waiters_keep_their_turn_ahead_of_new_arrivals() {
        let slots = Arc::new(Semaphore::new(1));
        let held = slots.clone().acquire_owned().await.unwrap();
        let mut first = Box::pin(acquire(slots.clone(), 5000));
        let mut second = Box::pin(acquire(slots.clone(), 5000));
        assert!(poll(first.as_mut()).is_pending());
        assert!(poll(second.as_mut()).is_pending());
        drop(held);
        assert!(acquire(slots.clone(), 0).await.is_none());
        assert!(poll(second.as_mut()).is_pending());
        let first = first.await.unwrap();
        assert_eq!(slots.available_permits(), 0);
        drop(first);
        let second = second.await.unwrap();
        assert_eq!(slots.available_permits(), 0);
        drop(second);
        assert_eq!(slots.available_permits(), 1);
    }

    #[tokio::test]
    async fn cancellation_releases_an_assigned_reservation_to_the_next_waiter() {
        let slots = Arc::new(Semaphore::new(1));
        let held = slots.clone().acquire_owned().await.unwrap();
        let mut cancelled = Box::pin(acquire(slots.clone(), 5000));
        let mut next = Box::pin(acquire(slots.clone(), 5000));
        assert!(poll(cancelled.as_mut()).is_pending());
        assert!(poll(next.as_mut()).is_pending());
        drop(held);
        // The cancelled future owns a queue reservation but has not returned a
        // permit to its caller. Dropping it must still restore that capacity.
        drop(cancelled);
        drop(next.await.unwrap());
        assert_eq!(slots.available_permits(), 1);
    }

    #[tokio::test]
    async fn timeout_removes_the_waiter_without_leaking_capacity() {
        let slots = Arc::new(Semaphore::new(1));
        let held = slots.clone().acquire_owned().await.unwrap();
        assert!(acquire(slots.clone(), 10).await.is_none());
        assert_eq!(slots.available_permits(), 0);
        drop(held);
        let next = acquire(slots.clone(), 1000).await.unwrap();
        drop(next);
        assert_eq!(slots.available_permits(), 1);
    }
}
