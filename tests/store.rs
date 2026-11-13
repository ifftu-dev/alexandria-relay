//! Black-box tests for the persistent store: the DHT record mirror across
//! restarts, and HTTP lookups while the store is busy.
//!
//! The DHT client here speaks only Kademlia; it lives in this file so the
//! shared harness stays protocol-neutral.

mod common;

use std::time::{Duration, Instant};

use common::{TempDir, TestRelay, STEP_TIMEOUT};
use futures::StreamExt;
use libp2p::kad::{self, store::MemoryStore, GetRecordOk, QueryResult, Quorum, Record, RecordKey};
use libp2p::multiaddr::Protocol;
use libp2p::swarm::SwarmEvent;
use libp2p::{noise, tcp, yamux, Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder};

/// The relay's Kademlia protocol: the wire contract with the app.
const KAD_PROTOCOL: &str = "/alexandria/kad/1.0";

/// A libp2p node that only speaks Kademlia, in client mode.
struct DhtClient {
    swarm: Swarm<kad::Behaviour<MemoryStore>>,
}

fn relay_peer(addr: &Multiaddr) -> PeerId {
    addr.iter()
        .find_map(|p| match p {
            Protocol::P2p(peer) => Some(peer),
            _ => None,
        })
        .expect("relay address carries /p2p")
}

impl DhtClient {
    fn new() -> Self {
        let swarm = SwarmBuilder::with_new_identity()
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .expect("client TCP transport")
            .with_behaviour(|key| {
                let peer = key.public().to_peer_id();
                let config = kad::Config::new(StreamProtocol::new(KAD_PROTOCOL));
                let mut kad = kad::Behaviour::with_config(peer, MemoryStore::new(peer), config);
                kad.set_mode(Some(kad::Mode::Client));
                kad
            })
            .expect("client behaviour")
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();
        DhtClient { swarm }
    }

    fn peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    /// A record published by this client, expiring `ttl` from now.
    fn record(&self, key: &[u8], value: &[u8], ttl: Duration) -> Record {
        Record {
            key: RecordKey::new(&key),
            value: value.to_vec(),
            publisher: Some(self.peer_id()),
            expires: Some(Instant::now() + ttl),
        }
    }

    /// Put each record to the relay at `relay_addr` and wait for every
    /// put to finish. Returns how many the relay acknowledged.
    async fn put_all(&mut self, relay_addr: &Multiaddr, records: Vec<Record>) -> usize {
        let relay = relay_peer(relay_addr);
        self.swarm
            .behaviour_mut()
            .add_address(&relay, relay_addr.clone());
        let mut pending = std::collections::HashSet::new();
        for record in records {
            pending.insert(self.swarm.behaviour_mut().put_record_to(
                record,
                std::iter::once(relay),
                Quorum::One,
            ));
        }
        let mut acknowledged = 0;
        while !pending.is_empty() {
            if let SwarmEvent::Behaviour(kad::Event::OutboundQueryProgressed {
                id,
                result: QueryResult::PutRecord(result),
                ..
            }) = self.swarm.select_next_some().await
            {
                if pending.remove(&id) && result.is_ok() {
                    acknowledged += 1;
                }
            }
        }
        acknowledged
    }

    async fn put(&mut self, relay_addr: &Multiaddr, record: Record) {
        let acked = tokio::time::timeout(STEP_TIMEOUT, self.put_all(relay_addr, vec![record]))
            .await
            .expect("DHT put timed out");
        assert_eq!(acked, 1, "the relay acknowledged the put");
    }

    /// Ask the relay at `relay_addr` for `key`.
    async fn get(&mut self, relay_addr: &Multiaddr, key: &[u8]) -> Option<Record> {
        let relay = relay_peer(relay_addr);
        self.swarm
            .behaviour_mut()
            .add_address(&relay, relay_addr.clone());
        let query = self.swarm.behaviour_mut().get_record(RecordKey::new(&key));
        let outcome = async {
            loop {
                if let SwarmEvent::Behaviour(kad::Event::OutboundQueryProgressed {
                    id,
                    result: QueryResult::GetRecord(result),
                    ..
                }) = self.swarm.select_next_some().await
                {
                    if id != query {
                        continue;
                    }
                    return match result {
                        Ok(GetRecordOk::FoundRecord(found)) => Some(found.record),
                        _ => None,
                    };
                }
            }
        };
        tokio::time::timeout(STEP_TIMEOUT, outcome)
            .await
            .expect("DHT get timed out")
    }
}

/// Seconds until `record` expires, as the client sees it.
fn ttl_secs(record: &Record) -> Option<u64> {
    record
        .expires
        .map(|t| t.saturating_duration_since(Instant::now()).as_secs())
}

#[tokio::test]
async fn a_dht_put_survives_a_restart_with_its_expiry_and_publisher() {
    let data_dir = TempDir::new();
    let relay = TestRelay::start_in(&data_dir, |_| {}).await;
    let mut publisher = DhtClient::new();
    let ttl = Duration::from_secs(3600);
    publisher
        .put(
            &relay.tcp_addr(),
            publisher.record(b"profile/ada", b"hello", ttl),
        )
        .await;
    relay.stop().await;

    let relay = TestRelay::start_in(&data_dir, |_| {}).await;
    let record = DhtClient::new()
        .get(&relay.tcp_addr(), b"profile/ada")
        .await
        .expect("the record is served after a restart");
    assert_eq!(record.value, b"hello");
    assert_eq!(record.publisher, Some(publisher.peer_id()));
    let left = ttl_secs(&record).expect("the reloaded record keeps an expiry");
    assert!(
        (3600 - 120..=3600).contains(&left),
        "expiry drifted across the restart: {left}s left"
    );
    relay.stop().await;
}

#[tokio::test]
async fn an_expired_mirrored_record_is_absent_after_a_restart() {
    let data_dir = TempDir::new();
    let relay = TestRelay::start_in(&data_dir, |_| {}).await;
    let mut publisher = DhtClient::new();
    let relay_addr = relay.tcp_addr();
    let records = vec![
        publisher.record(b"lasting", b"1", Duration::from_secs(3600)),
        publisher.record(b"fleeting", b"2", Duration::from_secs(2)),
    ];
    let acked = tokio::time::timeout(STEP_TIMEOUT, publisher.put_all(&relay_addr, records))
        .await
        .expect("DHT puts timed out");
    assert_eq!(acked, 2);
    relay.stop().await;
    tokio::time::sleep(Duration::from_secs(3)).await;

    let relay = TestRelay::start_in(&data_dir, |_| {}).await;
    let mut reader = DhtClient::new();
    assert!(
        reader.get(&relay.tcp_addr(), b"lasting").await.is_some(),
        "the live record is still served"
    );
    assert!(
        reader.get(&relay.tcp_addr(), b"fleeting").await.is_none(),
        "the expired record came back after the restart"
    );
    relay.stop().await;
}

/// How long one lookup may take while the store is busy. Generous for a
/// debug build on a loaded CI runner; a lookup stuck behind the event loop
/// or a lock takes far longer, or times out.
const BUSY_LOOKUP_BOUND: Duration = Duration::from_secs(1);

// One runtime thread for relay, client and lookups alike: the one-vCPU case,
// where any store work done on the runtime delays every other task.
#[tokio::test]
async fn lookups_answer_while_a_burst_of_dht_puts_is_in_flight() {
    // Lift the lookup budget: this test is about the store, not the limiter.
    let relay = TestRelay::start_with(|c| c.limits.lookup_limit = usize::MAX).await;
    let relay_addr = relay.tcp_addr();
    let mut publisher = DhtClient::new();
    let value = vec![7u8; 4096];
    let records: Vec<Record> = (0..2000)
        .map(|i| {
            publisher.record(
                format!("burst/{i}").as_bytes(),
                &value,
                Duration::from_secs(3600),
            )
        })
        .collect();
    let burst = tokio::spawn(async move { publisher.put_all(&relay_addr, records).await });

    let mut lookups = 0;
    let mut slowest = Duration::ZERO;
    while !burst.is_finished() || lookups < 5 {
        let started = Instant::now();
        let (status, body) = relay.get("/username/ada_99", None).await;
        slowest = slowest.max(started.elapsed());
        assert_eq!(status, 200, "{body}");
        assert!(body.contains("\"available\":true"), "{body}");
        lookups += 1;
    }
    let acked = tokio::time::timeout(STEP_TIMEOUT, burst)
        .await
        .expect("DHT burst timed out")
        .expect("burst task");
    assert!(acked > 0, "the burst reached the relay");
    assert!(
        slowest < BUSY_LOOKUP_BOUND,
        "slowest of {lookups} lookups took {slowest:?}"
    );
    relay.stop().await;
}

#[tokio::test]
async fn a_lookup_the_store_cannot_answer_does_not_report_the_name_free() {
    // A regular file where the data directory should be: the store cannot
    // open, and the relay runs without receipts. Not knowing who holds a
    // name must not read as "nobody does".
    let dir = TempDir::new();
    let not_a_dir = dir.path().join("occupied");
    std::fs::write(&not_a_dir, b"not a directory").unwrap();
    let relay = TestRelay::start_with(|c| c.data_dir = not_a_dir).await;

    let (status, body) = relay.get("/username/ada_99", None).await;
    assert_eq!(status, 503, "{body}");
    assert!(!body.contains("\"available\""), "{body}");

    relay.stop().await;
}
