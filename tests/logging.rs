//! Log volume: with the default `info` filter, serving clients must not add
//! a log line per reservation or receipt request. Checked by the level of
//! the records the relay emits, not by their text.
//!
//! One test per binary: the logger is process-global.

mod common;

use std::sync::Mutex;

use common::{signed_claim, TestClient, TestRelay};

/// Records the level of every relay record at `info` or above.
struct LevelRecorder {
    records: Mutex<Vec<log::Level>>,
}

impl log::Log for LevelRecorder {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Info
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) && record.target().starts_with("alexandria_relay") {
            self.records.lock().unwrap().push(record.level());
        }
    }

    fn flush(&self) {}
}

static RECORDER: LevelRecorder = LevelRecorder {
    records: Mutex::new(Vec::new()),
};

fn records_since(mark: usize) -> Vec<log::Level> {
    RECORDER.records.lock().unwrap()[mark..].to_vec()
}

#[tokio::test]
async fn serving_clients_logs_nothing_per_event_at_the_default_level() {
    log::set_logger(&RECORDER).expect("first logger in this binary");
    log::set_max_level(log::LevelFilter::Info);

    let relay = TestRelay::start_with(|c| c.public_host = Some("localhost".to_string())).await;
    let relay_addr = relay.tcp_addr();
    let mark = RECORDER.records.lock().unwrap().len();

    let mut client = TestClient::new();
    client
        .reserve(&relay_addr)
        .await
        .expect("reservation accepted");
    for n in 0..3 {
        let claim = signed_claim(1, &format!("ada_{n}"), 1_700_000_000);
        client.request_receipt(&relay_addr, &claim).await;
    }

    let during = records_since(mark);
    assert!(
        during.is_empty(),
        "per-event records at info or above: {during:?}"
    );

    relay.stop().await;
}
