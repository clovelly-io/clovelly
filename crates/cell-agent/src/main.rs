//! The cell agent: boots the cell (attestation, unlock, cell API listener) and, on the
//! test image, runs the in-guest harness.
//!
//! ```text
//! cell-agent                          the cell: boot sequence, then serve (prod image)
//! cell-agent boot [--hold-on-failure] [--evidence DIR]
//!                                     the same, as the test harness's child
//! cell-agent harness --out DIR ...    runs the in-guest checks (test image)
//! cell-agent test-cell                the cell, with memory scans at its end (test image)
//! cell-agent impostor --mode M --name N
//!                                     an unverified cell for the SDK to refuse (test image)
//! cell-agent bench [--peer IP:PORT]   microbenchmarks, in a sandbox and on the host
//! cell-agent sink --listen IP:PORT    TCP sink for the transfer benchmark (peer VM)
//! cell-agent dest                     the header-logging test destination (test image)
//! cell-agent bench-http --to IP:PORT --bytes N --count C [--tcp-recovery V]
//! cell-agent bench-hold --to IP:PORT --connections N
//!                                     phase 3's in-sandbox throughput clients
//! cell-agent h2-client --url https://HOST[:PORT]/PATH [--header 'n: v']... [--bidi N] [--bytes B]
//!                                     phase 4's in-sandbox HTTP/2 client
//! ```

mod agent;
mod bench;
mod boot;
mod cellapi;
mod cgroup;
mod clock;
mod credentials;
mod dest;
#[cfg(feature = "dev")]
mod dev;
mod forwarded;
mod grpc;
#[cfg(test)]
mod guard;
mod h2client;
mod harness;
mod impostor;
mod latency;
mod lease;
mod listener;
mod metadata;
mod net;
mod phase1;
mod policies;
mod receipts;
mod report;
mod runsc;
mod sandbox;
mod scan;
mod stats;
mod storage;
mod templates;
mod testcell;
mod throughput;
mod tls;
mod tsm;
mod volumes;

use std::process::ExitCode;
use std::str::FromStr;

use anyhow::{Context, bail};

/// Unit tests run under the guard allocator, which counts freed blocks that still
/// hold a watched secret (criterion 10).
#[cfg(test)]
#[global_allocator]
static GUARD: guard::Guard = guard::Guard;

fn main() -> anyhow::Result<ExitCode> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("a rustls crypto provider is already installed"))?;
    let Some((cmd, rest)) = args.split_first() else {
        println!("cell-agent {}", env!("CARGO_PKG_VERSION"));
        return tokio::runtime::Runtime::new()?.block_on(agent::run(agent::Options::default()));
    };
    match cmd.as_str() {
        "boot" => {
            let opts = agent::Options {
                hold_on_failure: rest.iter().any(|a| a == "--hold-on-failure"),
                hold_on_end: rest.iter().any(|a| a == "--hold-on-end"),
                evidence: rest
                    .iter()
                    .position(|a| a == "--evidence")
                    .and_then(|i| rest.get(i + 1))
                    .map(Into::into),
            };
            tokio::runtime::Runtime::new()?.block_on(agent::run(opts))
        }
        "harness" => harness::run(&harness::Config::parse(rest)?).map(|()| ExitCode::SUCCESS),
        "test-cell" => testcell::run().map(|()| ExitCode::SUCCESS),
        #[cfg(feature = "dev")]
        "dev-serve" => {
            tokio::runtime::Runtime::new()?.block_on(dev::run(rest))?;
            Ok(ExitCode::SUCCESS)
        }
        "impostor" => {
            let flags = Flags::new(rest, &["--mode", "--name"])?;
            let mode: impostor::Mode = flags.require("--mode")?.parse()?;
            let name = flags.require("--name")?.to_owned();
            tokio::runtime::Runtime::new()?.block_on(impostor::run(mode, &name))?;
            Ok(ExitCode::SUCCESS)
        }
        "bench" => {
            let flags = Flags::new(rest, &["--peer", "--dir"])?;
            let dir = flags.get("--dir").unwrap_or("/work");
            bench::run(flags.parse("--peer")?, dir.as_ref())?;
            Ok(ExitCode::SUCCESS)
        }
        "sink" => {
            let listen = Flags::new(rest, &["--listen"])?.parse("--listen")?;
            bench::sink(listen.context("--listen is required")?)?;
            Ok(ExitCode::SUCCESS)
        }
        "dest" => {
            tokio::runtime::Runtime::new()?.block_on(dest::run())?;
            Ok(ExitCode::SUCCESS)
        }
        "bench-http" => {
            let f = Flags::new(rest, &["--to", "--bytes", "--count", "--tcp-recovery"])?;
            let to = f.parse("--to")?.context("--to is required")?;
            let (bytes, count) = (f.parse("--bytes")?.unwrap_or(100_000_000), f.parse("--count")?.unwrap_or(10));
            bench::http(to, bytes, count, f.parse("--tcp-recovery")?)?;
            Ok(ExitCode::SUCCESS)
        }
        "bench-hold" => {
            let f = Flags::new(rest, &["--to", "--connections"])?;
            let to = f.parse("--to")?.context("--to is required")?;
            bench::hold(to, f.parse("--connections")?.unwrap_or(143))?;
            Ok(ExitCode::SUCCESS)
        }
        "h2-client" => h2client::run(rest),
        other => bail!("unknown command {other:?}; expected boot, harness, test-cell, impostor, dest, bench, bench-http, bench-hold or sink"),
    }
}

/// `--name value` pairs, checked against the names a command accepts.
pub(crate) struct Flags<'a> {
    pairs: Vec<(&'a str, &'a str)>,
}

impl<'a> Flags<'a> {
    pub(crate) fn new(args: &'a [String], known: &[&str]) -> anyhow::Result<Self> {
        let mut pairs = Vec::new();
        let mut it = args.iter();
        while let Some(name) = it.next() {
            if !known.contains(&name.as_str()) {
                bail!("unknown flag {name:?}; expected one of {known:?}");
            }
            let value = it.next().with_context(|| format!("{name} needs a value"))?;
            pairs.push((name.as_str(), value.as_str()));
        }
        Ok(Self { pairs })
    }

    pub(crate) fn get(&self, name: &str) -> Option<&'a str> {
        self.pairs
            .iter()
            .rev()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| *v)
    }

    pub(crate) fn require(&self, name: &str) -> anyhow::Result<&'a str> {
        self.get(name)
            .with_context(|| format!("{name} is required"))
    }

    pub(crate) fn parse<T>(&self, name: &str) -> anyhow::Result<Option<T>>
    where
        T: FromStr,
        T::Err: std::error::Error + Send + Sync + 'static,
    {
        self.get(name)
            .map(|v| v.parse().with_context(|| format!("{name} {v:?}")))
            .transpose()
    }

    /// A comma-separated list.
    pub(crate) fn list<T>(&self, name: &str) -> anyhow::Result<Option<Vec<T>>>
    where
        T: FromStr,
        T::Err: Into<anyhow::Error>,
    {
        self.get(name)
            .map(|v| {
                v.split(',')
                    .map(|item| {
                        item.parse()
                            .map_err(Into::into)
                            .with_context(|| format!("{name} item {item:?}"))
                    })
                    .collect()
            })
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn flags_parse_known_pairs() {
        let a = args("--samples 200 --concurrency 1,10,50");
        let f = Flags::new(&a, &["--samples", "--concurrency"]).unwrap();
        assert_eq!(f.parse::<usize>("--samples").unwrap(), Some(200));
        assert_eq!(
            f.list::<usize>("--concurrency").unwrap(),
            Some(vec![1, 10, 50])
        );
        assert_eq!(f.parse::<usize>("--missing").unwrap(), None);
    }

    #[test]
    fn flags_reject_unknown_and_dangling() {
        assert!(Flags::new(&args("--bogus 1"), &["--samples"]).is_err());
        assert!(Flags::new(&args("--samples"), &["--samples"]).is_err());
        let a = args("--samples ten");
        assert!(
            Flags::new(&a, &["--samples"])
                .unwrap()
                .parse::<usize>("--samples")
                .is_err()
        );
    }

    #[test]
    fn harness_config_defaults() {
        let cfg = harness::Config::parse(&args("--out /r --tests runsc,latency")).unwrap();
        assert_eq!(
            cfg.tests,
            vec![harness::Test::Runsc, harness::Test::Latency]
        );
        assert_eq!(cfg.concurrency, vec![1, 10, 20, 50]);
        assert_eq!(cfg.samples, 200);
        assert!(harness::Config::parse(&args("--out /r --tests nope")).is_err());
    }
}
