//! `clovelly-receipt`: the public receipt verifier (SPEC.md decision 9, phase 4 criterion 8).
//!
//! ```text
//! clovelly-receipt verify --receipt R --signature S --cell-cert C --ca CA --measurements M
//! ```
//!
//! - `R`: the receipt exactly as signed (its JCS canonical JSON bytes).
//! - `S`: the signature, raw (64 bytes) or as base64 or hex text.
//! - `C`: the cell certificate that signed it (DER or PEM), as the receipt log or the
//!   SDK returns it.
//! - `CA`: the environment CA certificate (PEM or DER), from the customer's own
//!   verifier.
//! - `M`: the published measurement set: a release policy (or any JSON with
//!   `releases: [{id, rtmr: [4 hex], mrtd?: [hex]}]`).
//!
//! What a pass means: the receipt's bytes are canonical and signed by the key in a
//! certificate the environment CA issued, valid when the receipt was signed, for the
//! receipt's environment, sub-environment and release; and the receipt's measurements
//! are that release's published ones. It does not rest on a quote in the receipt: the
//! CA issued the certificate only after the customer's verifier checked the cell's
//! quote against the same measurements. Prints one JSON line and exits 0 when the
//! receipt verifies, 1 when it does not, 2 on a usage error. The line includes
//! `cpu_share`, the CPU sharing factor the sandbox ran under: 1 for dedicated CPU and for
//! a receipt written before the field existed, F when its sub-environment shared CPU
//! among its own sandboxes (guarantee its CPU request divided by F).

use std::path::Path;
use std::process::ExitCode;

use anyhow::Context;
use common::receipt::{self, MeasurementSet};
use serde_json::json;

fn usage() -> ExitCode {
    eprintln!("usage: clovelly-receipt verify --receipt FILE --signature FILE --cell-cert FILE --ca FILE (one CA or a bundle) --measurements FILE");
    ExitCode::from(2)
}

/// The certificates of a file as DER, whether it holds DER or PEM, and in PEM one or
/// several: a customer's CA bundle holds its old and new CA after a rotation.
fn certificates(path: &Path) -> anyhow::Result<Vec<Vec<u8>>> {
    let bytes = std::fs::read(path).with_context(|| path.display().to_string())?;
    match std::str::from_utf8(&bytes).ok().filter(|t| t.contains("-----BEGIN CERTIFICATE-----")) {
        Some(text) => Ok(common::b64::pem_blocks(text, "CERTIFICATE")?),
        None => Ok(vec![bytes]),
    }
}

/// A certificate file's first certificate as DER.
fn certificate(path: &Path) -> anyhow::Result<Vec<u8>> {
    certificates(path)?.into_iter().next().with_context(|| format!("{}: no certificate", path.display()))
}

/// A signature file: 64 raw bytes, or base64 or hex text of them.
fn signature(path: &Path) -> anyhow::Result<Vec<u8>> {
    let bytes = std::fs::read(path).with_context(|| path.display().to_string())?;
    if bytes.len() == 64 {
        return Ok(bytes);
    }
    let text = std::str::from_utf8(&bytes).context("the signature is neither 64 bytes nor text")?.trim();
    if let Some(raw) = common::unhex(text) {
        return Ok(raw);
    }
    Ok(common::b64::decode(text)?)
}

fn verify(args: &[String]) -> anyhow::Result<receipt::Verified> {
    let get = |name: &str| -> anyhow::Result<String> {
        let i = args.iter().position(|a| a == name).with_context(|| format!("{name} is required"))?;
        args.get(i + 1).cloned().with_context(|| format!("{name} needs a value"))
    };
    let receipt = std::fs::read(get("--receipt")?).context("--receipt")?;
    let sig = signature(get("--signature")?.as_ref())?;
    let cell = certificate(get("--cell-cert")?.as_ref())?;
    let cas = certificates(get("--ca")?.as_ref())?;
    let cas: Vec<&[u8]> = cas.iter().map(Vec::as_slice).collect();
    let set = MeasurementSet::from_json(&std::fs::read(get("--measurements")?).context("--measurements")?)?;
    Ok(receipt::verify_any(&receipt, &sig, &cell, &cas, &set)?)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(("verify", rest)) = args.split_first().map(|(c, r)| (c.as_str(), r)) else { return usage() };
    if rest.len() % 2 != 0 {
        return usage();
    }
    match verify(rest) {
        Ok(v) => {
            let d = &v.doc;
            let line = json!({
                "ok": true,
                "sandbox": v.sandbox_id(),
                "exit": v.exit_kind(),
                "env": v.cert.env.as_str(),
                "subenv": v.cert.subenv.as_str(),
                "release": v.cert.release.as_str(),
                "cpu_share": v.cpu_share,
                "template_digest": d["sandbox"]["template_digest"],
                "egress_log_hash": d["egress_log_hash"],
                "signed": d["signed"],
            });
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            println!("{}", json!({ "ok": false, "error": format!("{e:#}") }));
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn signatures_are_read_raw_hex_or_base64() {
        let dir = std::env::temp_dir().join(format!("clovelly-receipt-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let raw: Vec<u8> = (0..64).collect();
        for (name, bytes) in [
            ("raw", raw.clone()),
            ("hex", common::hex(&raw).into_bytes()),
            ("b64", format!("{}\n", common::b64::encode(&raw)).into_bytes()),
        ] {
            let p = dir.join(name);
            std::fs::write(&p, bytes).unwrap();
            assert_eq!(super::signature(&p).unwrap(), raw, "{name}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
