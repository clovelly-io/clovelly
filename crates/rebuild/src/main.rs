//! `clovelly-rebuild`: compares builds of a release.
//!
//! ```text
//! clovelly-rebuild compare A.txt B.txt      two builders' records must match in every
//!                                           field but `builder`; exits 1 on any
//!                                           difference (the release pipeline's gate,
//!                                           before anything is signed)
//! clovelly-rebuild match --build B.txt --bundle FB --release-key PEM --rekor-key PEM
//!                                           REPRODUCE.md's last step: checks the
//!                                           release's fragment and Rekor entry, then
//!                                           compares its payload with a rebuild
//! ```

use anyhow::{Context, bail};
use common::jws::{self, TrustedKey};
use common::release::{Fragment, FragmentBundle, ReleasePayload};
use rebuild::record::{self, BuildRecord};
use verifier::fragments;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["compare", a, b] => compare(a, b),
        ["match", rest @ ..] => matches(&Flags(rest)),
        _ => bail!("usage: clovelly-rebuild compare A.txt B.txt | match --build B.txt --bundle FB --release-key PEM --rekor-key PEM"),
    }
}

fn compare(pa: &str, pb: &str) -> anyhow::Result<()> {
    let lines = record::compare(&read_record(pa)?, &read_record(pb)?);
    for l in &lines {
        println!("{l}");
    }
    let bad = lines.iter().filter(|l| !l.ok()).count();
    if bad > 0 {
        bail!("{bad} of {} fields differ between {pa} and {pb}: refusing to sign", lines.len());
    }
    println!("all {} fields match: the builds are identical", lines.len());
    Ok(())
}

/// Checks the bundle as a customer's verifier does, then compares the logged payload
/// with the rebuild's prod image, one line per field.
fn matches(a: &Flags<'_>) -> anyhow::Result<()> {
    let b: FragmentBundle = serde_json::from_slice(&read(a.get("--bundle")?)?).context("--bundle")?;
    let (ours, log) = (key(a.get("--release-key")?)?, key(a.get("--rekor-key")?)?);
    fragments::verify(&b, std::slice::from_ref(&ours), std::slice::from_ref(&log))?;
    let f: Fragment = serde_json::from_slice(&jws::verify(&b.fragment, std::slice::from_ref(&ours))?)?;
    let p = ReleasePayload::parse(&common::b64::decode(&f.payload)?)?;
    let r = read_record(a.get("--build")?)?;
    let pairs = [
        ("release", p.release.to_string(), r.prod.release.to_string()),
        ("commit", p.provenance.source.commit.to_string(), r.commit.to_string()),
        ("recipe", p.recipe.to_string(), r.prod.recipe.to_string()),
        ("disk_sha256", p.provenance.disk_sha256.to_string(), r.prod.disk_sha256.to_string()),
        ("rtmr1", p.measurements.rtmr1.to_string(), r.prod.rtmr1.to_string()),
        ("rtmr2", p.measurements.rtmr2.to_string(), r.prod.rtmr2.to_string()),
    ];
    // Releases before 0.4.0 logged no container images.
    let images = p.images.iter().flat_map(|i| {
        [
            ("verifier image", i.verifier.to_string(), r.images.verifier.to_string()),
            ("clovelly-keys image", i.clovelly_keys.to_string(), r.images.clovelly_keys.to_string()),
        ]
    });
    let pairs: Vec<_> = pairs.into_iter().chain(images).collect();
    let mut differ = 0;
    for (k, logged, rebuilt) in &pairs {
        if logged == rebuilt {
            println!("match     {k:<20} {logged}");
        } else {
            differ += 1;
            println!("DIFFERENT {k:<20} logged {logged}, rebuilt {rebuilt}");
        }
    }
    if differ > 0 {
        bail!("{differ} of {} fields differ from the logged release", pairs.len());
    }
    println!("the rebuild matches {} as logged in Rekor at index {}", p.release, b.rekor.as_ref().map_or(0, |e| e.log_index));
    Ok(())
}

/// `--name value` pairs.
struct Flags<'a>(&'a [&'a str]);

impl Flags<'_> {
    fn get(&self, name: &str) -> anyhow::Result<&str> {
        self.0.iter().position(|a| *a == name).and_then(|i| self.0.get(i + 1)).copied().with_context(|| format!("{name} is required"))
    }
}

fn read(path: &str) -> anyhow::Result<Vec<u8>> {
    std::fs::read(path).with_context(|| path.to_owned())
}

fn read_record(path: &str) -> anyhow::Result<BuildRecord> {
    BuildRecord::parse(&String::from_utf8(read(path)?)?).with_context(|| path.to_owned())
}

fn key(path: &str) -> anyhow::Result<TrustedKey> {
    Ok(TrustedKey::from_pem(&String::from_utf8(read(path)?)?)?)
}
