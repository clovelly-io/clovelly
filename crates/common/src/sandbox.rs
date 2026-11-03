//! Sandbox sizes, the sub-environment's sandbox limits and the placement rule, shared
//! by the cell (which enforces them) and the control plane (which places by them).
//!
//! - [`Size`]: vCPUs in halves and whole GiB, the units of `CreateSandbox` (SPEC.md
//!   "Sandbox sizing").
//! - [`Limits`]: the policy bundle's default and maximum size and maximum timeout.
//! - [`check_window`]: a cell accepts a sandbox only if `now + timeout <= cell_end` and
//!   `now + timeout < valid_until` (SPEC.md "Cell cap and sandbox timeouts").

use std::ops::{Add, Sub};
use std::time::{Duration, SystemTime};

use serde::Deserialize;

/// The longest sandbox timeout (24 hours).
pub const MAX_TIMEOUT: Duration = Duration::from_secs(24 * 3600);
/// The longest a cell lives after its unlock (48 hours).
pub const MAX_CELL_CAP: Duration = Duration::from_secs(48 * 3600);
/// What a cell keeps for the kernel, cell-agent, egress-proxy and the template cache.
pub const CELL_RESERVATION: Size = Size::new(CpuHalves(2), MemoryGib(4));

/// vCPUs in halves: `CpuHalves(2)` is one vCPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CpuHalves(pub u32);

/// Memory in whole GiB.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemoryGib(pub u32);

impl CpuHalves {
    /// As vCPUs, for display and cgroup arithmetic.
    pub fn vcpus(self) -> f64 {
        f64::from(self.0) / 2.0
    }
}

impl MemoryGib {
    pub fn bytes(self) -> u64 {
        u64::from(self.0) << 30
    }
}

/// A sandbox's size, or a cell's capacity in the same units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Size {
    pub cpu: CpuHalves,
    pub memory: MemoryGib,
}

impl Size {
    pub const ZERO: Size = Size::new(CpuHalves(0), MemoryGib(0));

    pub const fn new(cpu: CpuHalves, memory: MemoryGib) -> Self {
        Self { cpu, memory }
    }

    /// Whether `self` fits within `room`, dimension by dimension.
    pub fn fits_in(self, room: Size) -> bool {
        self.cpu <= room.cpu && self.memory <= room.memory
    }

    /// Neither dimension is zero.
    pub fn is_nonzero(self) -> bool {
        self.cpu.0 > 0 && self.memory.0 > 0
    }
}

impl Add for Size {
    type Output = Size;

    fn add(self, o: Size) -> Size {
        Size::new(CpuHalves(self.cpu.0 + o.cpu.0), MemoryGib(self.memory.0 + o.memory.0))
    }
}

/// Saturating: capacity never goes below zero.
impl Sub for Size {
    type Output = Size;

    fn sub(self, o: Size) -> Size {
        Size::new(
            CpuHalves(self.cpu.0.saturating_sub(o.cpu.0)),
            MemoryGib(self.memory.0.saturating_sub(o.memory.0)),
        )
    }
}

/// Why a sandbox's window does not fit a cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Crossing {
    #[error("now + timeout is after the cell's end")]
    CellEnd,
    #[error("now + timeout is not before the release's valid_until")]
    ReleaseExpiry,
}

/// The placement rule: a sandbox of `timeout` started `now` fits a cell that ends at
/// `cell_end` running a release valid until `valid_until` only if
/// `now + timeout <= cell_end` and `now + timeout < valid_until`, so neither the cap nor
/// a release expiry can end it.
pub fn check_window(
    now: SystemTime,
    timeout: Duration,
    cell_end: SystemTime,
    valid_until: SystemTime,
) -> Result<(), Crossing> {
    let end = now + timeout;
    if end > cell_end {
        return Err(Crossing::CellEnd);
    }
    if end >= valid_until {
        return Err(Crossing::ReleaseExpiry);
    }
    Ok(())
}

/// A request above a sub-environment's maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AboveMaximum {
    #[error("cpu {} vCPU is above the maximum {} vCPU", .0.vcpus(), .1.vcpus())]
    Cpu(CpuHalves, CpuHalves),
    #[error("memory {} GiB is above the maximum {} GiB", .0.0, .1.0)]
    Memory(MemoryGib, MemoryGib),
    #[error("timeout {0:?} is above the maximum {1:?}")]
    Timeout(Duration, Duration),
}

#[derive(Debug, thiserror::Error)]
pub enum LimitsError {
    #[error("policy bundle JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("cpu {0} is not a positive multiple of 0.5 vCPU")]
    Cpu(f64),
    #[error("memory must be at least 1 GiB")]
    Memory,
    #[error("timeout {0:?} must be 1 s to 24 h")]
    Timeout(Duration),
    #[error("the default size is above the maximum")]
    DefaultAboveMax,
}

/// A sub-environment's sandbox limits, from its policy bundle:
///
/// ```json
/// { "sandbox": { "default": { "cpu": 1, "memory": 2 },
///                "max": { "cpu": 7, "memory": 28, "timeout": 86400 } } }
/// ```
///
/// `cpu` is in vCPUs (a multiple of 0.5), `memory` in GiB, `timeout` in seconds. A
/// bundle without `sandbox` gets the product defaults: 1 vCPU and 2 GiB by default,
/// `max` the given ceiling (a cell's placeable capacity) and 24 hours.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub default: Size,
    pub max: Size,
    pub max_timeout: Duration,
}

/// The product default size: 1 vCPU and 2 GiB.
pub const DEFAULT_SIZE: Size = Size::new(CpuHalves(2), MemoryGib(2));
/// The product default timeout when a request names none (the SDK sketch's 900 s).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(900);

#[derive(Deserialize)]
struct Bundle {
    sandbox: Option<WireLimits>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireLimits {
    default: WireSize,
    max: WireMax,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSize {
    cpu: f64,
    memory: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireMax {
    cpu: f64,
    memory: u32,
    timeout: u64,
}

fn halves(cpu: f64) -> Result<CpuHalves, LimitsError> {
    let h = cpu * 2.0;
    if !(h >= 1.0 && h.fract() == 0.0 && h <= f64::from(u16::MAX)) {
        return Err(LimitsError::Cpu(cpu));
    }
    // In range and integral, so the cast is exact.
    Ok(CpuHalves(h as u32))
}

fn size(cpu: f64, memory: u32) -> Result<Size, LimitsError> {
    if memory == 0 {
        return Err(LimitsError::Memory);
    }
    Ok(Size::new(halves(cpu)?, MemoryGib(memory)))
}

impl Limits {
    /// Reads the `sandbox` section of a policy bundle; `ceiling` is the maximum size
    /// when the bundle names none.
    pub fn from_bundle(json: &[u8], ceiling: Size) -> Result<Self, LimitsError> {
        let Some(w) = serde_json::from_slice::<Bundle>(json)?.sandbox else {
            return Ok(Self {
                default: DEFAULT_SIZE,
                max: ceiling,
                max_timeout: MAX_TIMEOUT,
            });
        };
        let max_timeout = Duration::from_secs(w.max.timeout);
        if max_timeout.is_zero() || max_timeout > MAX_TIMEOUT {
            return Err(LimitsError::Timeout(max_timeout));
        }
        let limits = Self {
            default: size(w.default.cpu, w.default.memory)?,
            max: size(w.max.cpu, w.max.memory)?,
            max_timeout,
        };
        if !limits.default.fits_in(limits.max) {
            return Err(LimitsError::DefaultAboveMax);
        }
        Ok(limits)
    }

    /// Refuses a size or timeout above the maximum.
    pub fn check(&self, size: Size, timeout: Duration) -> Result<(), AboveMaximum> {
        if size.cpu > self.max.cpu {
            return Err(AboveMaximum::Cpu(size.cpu, self.max.cpu));
        }
        if size.memory > self.max.memory {
            return Err(AboveMaximum::Memory(size.memory, self.max.memory));
        }
        if timeout > self.max_timeout {
            return Err(AboveMaximum::Timeout(timeout, self.max_timeout));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOUR: Duration = Duration::from_secs(3600);

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    /// Criteria 5 and 16: a timeout reaching past the cell's end or to the release's
    /// valid_until is refused; one that ends exactly at the cell's end fits.
    #[test]
    fn placement_refuses_a_timeout_past_the_cap_or_valid_until() {
        let now = at(1_000_000);
        let cell_end = now + 30 * 60 * Duration::from_secs(1);
        let valid_until = now + 20 * HOUR;
        let ok = |t: Duration| check_window(now, t, cell_end, valid_until);
        assert_eq!(ok(Duration::from_secs(60)), Ok(()));
        assert_eq!(ok(Duration::from_secs(30 * 60)), Ok(()), "ending at the cap fits");
        assert_eq!(ok(Duration::from_secs(30 * 60 + 1)), Err(Crossing::CellEnd));

        // A 24-hour timeout: accepted by a fresh cell with a 48-hour cap, refused by
        // the same cell once fewer than 24 hours of its cap remain.
        let unlock = now;
        let cap_end = unlock + 48 * HOUR;
        let far = unlock + 30 * 24 * HOUR;
        assert_eq!(check_window(unlock, MAX_TIMEOUT, cap_end, far), Ok(()));
        assert_eq!(check_window(unlock + 24 * HOUR, MAX_TIMEOUT, cap_end, far), Ok(()));
        assert_eq!(
            check_window(unlock + 24 * HOUR + Duration::from_secs(1), MAX_TIMEOUT, cap_end, far),
            Err(Crossing::CellEnd)
        );

        // The release expires first: ending at valid_until is already too late.
        let soon = now + Duration::from_secs(600);
        assert_eq!(check_window(now, Duration::from_secs(599), cap_end, soon), Ok(()));
        assert_eq!(check_window(now, Duration::from_secs(600), cap_end, soon), Err(Crossing::ReleaseExpiry));
    }

    #[test]
    fn limits_parse_from_a_bundle_and_refuse_above_maximum() {
        let bundle = br#"{"v":1,"env":"staging","subenv":"a","destinations":[],
            "sandbox":{"default":{"cpu":1,"memory":2},"max":{"cpu":3.5,"memory":8,"timeout":3600}}}"#;
        let l = Limits::from_bundle(bundle, Size::new(CpuHalves(14), MemoryGib(28))).unwrap();
        assert_eq!(l.default, DEFAULT_SIZE);
        assert_eq!(l.max, Size::new(CpuHalves(7), MemoryGib(8)));
        assert_eq!(l.check(Size::new(CpuHalves(7), MemoryGib(8)), HOUR), Ok(()));
        assert_eq!(
            l.check(Size::new(CpuHalves(8), MemoryGib(1)), HOUR),
            Err(AboveMaximum::Cpu(CpuHalves(8), CpuHalves(7)))
        );
        assert!(matches!(l.check(DEFAULT_SIZE, HOUR * 2), Err(AboveMaximum::Timeout(..))));

        let none = Limits::from_bundle(br#"{"v":1}"#, Size::new(CpuHalves(14), MemoryGib(28))).unwrap();
        assert_eq!(none.max_timeout, MAX_TIMEOUT);
        for bad in [
            r#"{"sandbox":{"default":{"cpu":0.3,"memory":2},"max":{"cpu":7,"memory":28,"timeout":60}}}"#,
            r#"{"sandbox":{"default":{"cpu":1,"memory":0},"max":{"cpu":7,"memory":28,"timeout":60}}}"#,
            r#"{"sandbox":{"default":{"cpu":1,"memory":2},"max":{"cpu":7,"memory":28,"timeout":90000}}}"#,
            r#"{"sandbox":{"default":{"cpu":8,"memory":2},"max":{"cpu":7,"memory":28,"timeout":60}}}"#,
        ] {
            assert!(Limits::from_bundle(bad.as_bytes(), Size::ZERO).is_err(), "{bad}");
        }
    }
}
