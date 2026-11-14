//! Log volume: serving clients logs one line per reservation and per receipt
//! request, at debug on a per-kind target under `alexandria_relay::event`,
//! and nothing per event at the default `info` level. Checked by the target
//! and level of the records the relay emits, never by their text.
//!
//! One test per binary: the logger is process-global.

mod common;

use std::sync::Mutex;

use common::{signed_claim, TestClient, TestRelay};

/// The targets operators filter on, written out as the contract.
const RESERVATION_TARGET: &str = "alexandria_relay::event::reservation";
const RECEIPT_TARGET: &str = "alexandria_relay::event::receipt";
const EVENT_TARGETS: &str = "alexandria_relay::event::";

/// Records the target and level of every record from the relay's crate.
struct Recorder {
    records: Mutex<Vec<(String, log::Level)>>,
}

impl log::Log for Recorder {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.target().starts_with("alexandria_relay")
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            self.records
                .lock()
                .unwrap()
                .push((record.target().to_string(), record.level()));
        }
    }

    fn flush(&self) {}
}

static RECORDER: Recorder = Recorder {
    records: Mutex::new(Vec::new()),
};

fn records_since(mark: usize) -> Vec<(String, log::Level)> {
    RECORDER.records.lock().unwrap()[mark..].to_vec()
}

#[tokio::test]
async fn per_event_lines_are_emitted_at_debug_and_none_at_info() {
    log::set_logger(&RECORDER).expect("first logger in this binary");
    log::set_max_level(log::LevelFilter::Trace);

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
    let loud: Vec<_> = during
        .iter()
        .filter(|(_, level)| *level <= log::Level::Info)
        .collect();
    assert!(
        loud.is_empty(),
        "records at info or above while serving: {loud:?}"
    );

    let count = |target: &str| during.iter().filter(|(t, _)| t == target).count();
    assert!(
        count(RESERVATION_TARGET) >= 1,
        "no reservation line on {RESERVATION_TARGET}: {during:?}"
    );
    assert!(
        count(RECEIPT_TARGET) >= 3,
        "fewer than three receipt lines on {RECEIPT_TARGET}: {during:?}"
    );
    let off_level: Vec<_> = during
        .iter()
        .filter(|(t, level)| t.starts_with(EVENT_TARGETS) && *level != log::Level::Debug)
        .collect();
    assert!(
        off_level.is_empty(),
        "per-event lines not at debug: {off_level:?}"
    );

    relay.stop().await;
}
