#[allow(dead_code)]
mod common;

use std::{
    io::Write,
    sync::{Arc, Mutex},
    time::Duration,
};
use tracing::instrument::WithSubscriber;

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn standalone_cluster_task_stays_quiet_and_waits_for_shutdown() {
    let root = tempfile::tempdir().unwrap();
    let config = common::config(root.path());
    assert!(config.cluster.is_none());
    let store = noisefence::store::Store::open(&config.data_dir).unwrap();
    noisefence::cluster::prepare(&config, &store).await.unwrap();
    let control = noisefence::control::Controller::load(config, store)
        .await
        .unwrap();

    for close_sender in [false, true] {
        let captured = Capture::default();
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .without_time()
            .with_max_level(tracing::Level::WARN)
            .with_writer(move || writer.clone())
            .finish();
        let (stop, rx) = tokio::sync::watch::channel(false);
        let mut task =
            tokio::spawn(noisefence::cluster::run(control.clone(), rx).with_subscriber(subscriber));

        // The daemon treats an early background-task exit as a fatal error.
        // Observe longer than one coordinator poll interval to catch retries.
        assert!(
            tokio::time::timeout(Duration::from_millis(2100), &mut task)
                .await
                .is_err(),
            "standalone background task exited before shutdown"
        );
        if close_sender {
            drop(stop);
        } else {
            stop.send(true).unwrap();
        }
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .expect("standalone shutdown did not complete")
            .unwrap()
            .unwrap();
        let logs = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        assert!(logs.is_empty(), "unexpected standalone warnings: {logs}");
    }
}
