//! Percentiles over latency samples.

use std::time::Duration;

/// Summary of a set of samples. Percentiles use the nearest-rank method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Summary {
    pub n: usize,
    pub p50: Duration,
    pub p95: Duration,
    pub min: Duration,
    pub max: Duration,
}

impl Summary {
    /// Summarises `samples`, or `None` when there are none.
    pub fn of(samples: &[Duration]) -> Option<Self> {
        let mut sorted = samples.to_vec();
        sorted.sort_unstable();
        Some(Self {
            n: sorted.len(),
            p50: percentile(&sorted, 50)?,
            p95: percentile(&sorted, 95)?,
            min: *sorted.first()?,
            max: *sorted.last()?,
        })
    }
}

/// Nearest-rank percentile of ascending `sorted`: the smallest sample with at least
/// `p` percent of samples at or below it.
fn percentile(sorted: &[Duration], p: usize) -> Option<Duration> {
    let rank = (p * sorted.len()).div_ceil(100).max(1);
    sorted.get(rank - 1).copied()
}

/// Nearest-rank percentile of ascending `sorted` measurements (NaN when empty).
pub fn percentile_f64(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    // Nearest rank: ceil(p/100 * n), at least 1; n is small, so the cast is exact.
    let rank = ((p / 100.0 * sorted.len() as f64).ceil() as usize).max(1);
    sorted[rank.min(sorted.len()) - 1]
}

/// Milliseconds with microsecond precision, for tables.
pub fn ms(d: Duration) -> String {
    format!("{:.3}", d.as_secs_f64() * 1e3)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms_vec(v: &[u64]) -> Vec<Duration> {
        v.iter().map(|&m| Duration::from_millis(m)).collect()
    }

    #[test]
    fn nearest_rank_percentiles() {
        let s = Summary::of(&ms_vec(&(1..=200).rev().collect::<Vec<_>>())).unwrap();
        assert_eq!(s.n, 200);
        assert_eq!(s.p50, Duration::from_millis(100));
        assert_eq!(s.p95, Duration::from_millis(190));
        assert_eq!(
            (s.min, s.max),
            (Duration::from_millis(1), Duration::from_millis(200))
        );

        let one = Summary::of(&ms_vec(&[7])).unwrap();
        assert_eq!(
            (one.p50, one.p95),
            (Duration::from_millis(7), Duration::from_millis(7))
        );
    }

    #[test]
    fn empty_has_no_summary() {
        assert_eq!(Summary::of(&[]), None);
    }
}
