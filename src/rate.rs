//! The one window counter behind every per-client and per-peer rate limit:
//! new connections per client, receipt requests per peer and username
//! lookups per client.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

/// Hits counted per key in fixed windows. A key's window opens at its first
/// hit and covers `window` from then; the first hit at or after its end
/// opens a new one with the count back at one.
pub(crate) struct RateWindows<K> {
    windows: HashMap<K, (usize, Instant)>,
    window: Duration,
}

impl<K: Eq + Hash> RateWindows<K> {
    pub(crate) fn new(window: Duration) -> Self {
        RateWindows {
            windows: HashMap::new(),
            window,
        }
    }

    /// Count a hit for `key` at `now`. Returns the hits in the key's current
    /// window, this one included.
    pub(crate) fn hit(&mut self, key: K, now: Instant) -> usize {
        let (count, started) = self.windows.entry(key).or_insert((0, now));
        if now.saturating_duration_since(*started) >= self.window {
            *count = 0;
            *started = now;
        }
        *count += 1;
        *count
    }

    /// Forget every key whose window opened `age` or longer before `now`.
    pub(crate) fn forget_older_than(&mut self, now: Instant, age: Duration) {
        self.windows
            .retain(|_, (_, started)| now.saturating_duration_since(*started) < age);
    }

    /// The window length.
    pub(crate) fn window(&self) -> Duration {
        self.window
    }

    /// Keys currently tracked.
    pub(crate) fn len(&self) -> usize {
        self.windows.len()
    }

    pub(crate) fn clear(&mut self) {
        self.windows.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WINDOW: Duration = Duration::from_secs(60);

    #[test]
    fn hits_count_up_within_a_window_per_key() {
        let mut w = RateWindows::new(WINDOW);
        let t0 = Instant::now();
        assert_eq!(w.hit("a", t0), 1);
        assert_eq!(w.hit("a", t0 + Duration::from_secs(10)), 2);
        assert_eq!(w.hit("b", t0 + Duration::from_secs(10)), 1);
        assert_eq!(w.hit("a", t0 + Duration::from_secs(59)), 3);
    }

    #[test]
    fn a_window_ends_exactly_its_length_after_it_opened() {
        let mut w = RateWindows::new(WINDOW);
        let t0 = Instant::now();
        w.hit("a", t0);
        w.hit("a", t0 + Duration::from_secs(1));
        assert_eq!(w.hit("a", t0 + WINDOW), 1, "the count starts again");
        assert_eq!(w.hit("a", t0 + WINDOW + Duration::from_secs(59)), 2);
    }

    #[test]
    fn old_windows_are_forgotten() {
        let mut w = RateWindows::new(WINDOW);
        let t0 = Instant::now();
        w.hit("old", t0);
        w.hit("new", t0 + Duration::from_secs(100));
        w.forget_older_than(t0 + Duration::from_secs(120), 2 * WINDOW);
        assert_eq!(w.len(), 1);
        assert_eq!(w.hit("old", t0 + Duration::from_secs(120)), 1);
    }
}
