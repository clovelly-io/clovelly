//! The cgroup v2 layout that enforces sandbox sizes and the cell's reservation
//! (SPEC.md "Sandbox sizing").
//!
//! ```text
//! /sys/fs/cgroup                 cell-agent, runsc's own processes, the kernel's share
//! └── clovelly                       memory.max and cpu.max at the placeable capacity
//!     └── <sandbox id>           created by runsc from the sandbox's OCI spec:
//!                                memory.max, cpu.max (cap) and cpu.weight (guarantee)
//! ```
//!
//! The `clovelly` parent keeps the cell's 1 vCPU and 4 GiB for the kernel, cell-agent,
//! egress-proxy and the template cache even if sandbox accounting were wrong.

use std::fs;
use std::io;
use std::path::Path;

use common::ids::SandboxId;
use common::sandbox::{CELL_RESERVATION, CpuHalves, MemoryGib, Size};

const ROOT: &str = "/sys/fs/cgroup";
const PARENT: &str = "clovelly";
const CONTROLLERS: &str = "+cpu +memory +pids";

#[derive(Debug, thiserror::Error)]
pub enum CgroupError {
    #[error("{path}: {source}")]
    Io { path: String, source: io::Error },
    #[error("/proc/meminfo has no MemTotal")]
    NoMemTotal,
}

fn write(path: &Path, value: &str) -> Result<(), CgroupError> {
    fs::write(path, value).map_err(|source| CgroupError::Io {
        path: path.display().to_string(),
        source,
    })
}

/// The machine's size: its CPUs, and its memory rounded up to whole GiB (GCE sizes
/// machines in GiB; the kernel's MemTotal is a little less, which the reservation
/// absorbs).
pub fn machine() -> Result<Size, CgroupError> {
    let meminfo = fs::read_to_string("/proc/meminfo").map_err(|source| CgroupError::Io {
        path: "/proc/meminfo".into(),
        source,
    })?;
    let kib: u64 = meminfo
        .lines()
        .find_map(|l| l.strip_prefix("MemTotal:"))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
        .ok_or(CgroupError::NoMemTotal)?;
    let gib = kib.div_ceil(1 << 20);
    let cpus = std::thread::available_parallelism().map_or(1, usize::from);
    Ok(Size::new(
        CpuHalves(u32::try_from(cpus * 2).unwrap_or(u32::MAX)),
        MemoryGib(u32::try_from(gib).unwrap_or(u32::MAX)),
    ))
}

/// What sandboxes may use: the machine minus the cell's reservation.
pub fn placeable(machine: Size) -> Size {
    machine - CELL_RESERVATION
}

/// Creates `/sys/fs/cgroup/clovelly` capped at `placeable`, with the CPU, memory and pids
/// controllers delegated to its children.
pub fn setup(placeable: Size) -> Result<(), CgroupError> {
    let root = Path::new(ROOT);
    write(&root.join("cgroup.subtree_control"), CONTROLLERS)?;
    let parent = root.join(PARENT);
    if !parent.exists() {
        fs::create_dir(&parent).map_err(|source| CgroupError::Io {
            path: parent.display().to_string(),
            source,
        })?;
    }
    write(&parent.join("memory.max"), &placeable.memory.bytes().to_string())?;
    write(&parent.join("cpu.max"), &cpu_max(placeable.cpu))?;
    write(&parent.join("cgroup.subtree_control"), CONTROLLERS)
}

/// `cpu.max` for a CPU allowance: quota and period in microseconds.
fn cpu_max(cpu: CpuHalves) -> String {
    format!("{} 100000", u64::from(cpu.0) * 50_000)
}

/// A sandbox's cgroup, as its OCI spec's `cgroupsPath`.
pub fn sandbox_path(id: &SandboxId) -> String {
    format!("/{PARENT}/{id}")
}

/// Every sandbox together: CPU time used (microseconds, cumulative) and memory in use.
pub fn usage() -> Result<(u64, u64), CgroupError> {
    let parent = Path::new(ROOT).join(PARENT);
    let read = |name: &str| {
        let path = parent.join(name);
        fs::read_to_string(&path).map_err(|source| CgroupError::Io {
            path: path.display().to_string(),
            source,
        })
    };
    let usec = read("cpu.stat")?
        .lines()
        .find_map(|l| l.strip_prefix("usage_usec "))
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(0);
    let bytes = read("memory.current")?.trim().parse().unwrap_or(0);
    Ok((usec, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_c3_standard_8_places_7_vcpu_and_28_gib() {
        let machine = Size::new(CpuHalves(16), MemoryGib(32));
        assert_eq!(placeable(machine), Size::new(CpuHalves(14), MemoryGib(28)));
        assert_eq!(cpu_max(CpuHalves(14)), "700000 100000");
        assert_eq!(cpu_max(CpuHalves(1)), "50000 100000");
    }
}
