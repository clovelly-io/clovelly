//! The verifier binary.
//!
//! ```text
//! verifier [serve]                          the gRPC service (Cloud Run); reads
//!                                           CLOVELLY_CONFIG, CLOVELLY_RELEASE_POLICY and PORT
//!                                           (and, built with `test-clock` only,
//!                                           CLOVELLY_TEST_CLOCK_OFFSET_SECS)
//! verifier make-ca --kms-key KEY --env ENV  prints a new self-signed environment CA
//! verifier sign --kms-key KEY [--detached]  signs stdin as a JWS (ES256)
//! verifier public-key --kms-key KEY         prints a KMS key's public key (PEM)
//! ```
//!
//! The operator commands use the token in `CLOVELLY_ACCESS_TOKEN`
//! (`gcloud auth print-access-token`).

use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use common::release::FragmentBundle;
use serde_json::json;
use verifier::config::Config;
use verifier::jws::{self, TrustedKey};
use verifier::kms::{CloudKms, Kms, Token};
use verifier::policy::ReleasePolicy;
use verifier::service::{self, Clock, Service, VerifierServer};
use verifier::{HttpSources, Verifier};

/// The largest request the service decodes (an `AppendReceipt` batch).
const RECEIPT_BATCH_LIMIT: usize = 32 << 20;
/// How often fragments are fetched again and pinned releases checked for expiry.
const REFRESH: Duration = Duration::from_secs(600);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("a rustls crypto provider is already installed"))?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (cmd, rest) = args.split_first().map_or(("serve", &[][..]), |(c, r)| (c.as_str(), r));
    match cmd {
        "serve" => serve().await,
        "make-ca" => {
            let (key, env) = (flag(rest, "--kms-key")?, flag(rest, "--env")?);
            let der = verifier::x509::make_ca(&operator_kms()?, &key, &env, service::now()).await?;
            print!("{}", common::b64::pem("CERTIFICATE", &der));
            Ok(())
        }
        "sign" => {
            let key = flag(rest, "--kms-key")?;
            let mut payload = Vec::new();
            std::io::stdin().read_to_end(&mut payload)?;
            let input = jws::signing_input(&payload);
            let sig = operator_kms()?.sign(&key, input.as_bytes()).await?;
            println!("{}", jws::assemble(&payload, &sig, rest.iter().any(|a| a == "--detached"))?);
            Ok(())
        }
        "public-key" => {
            let key = flag(rest, "--kms-key")?;
            print!("{}", common::b64::pem("PUBLIC KEY", &operator_kms()?.public_key(&key).await?));
            Ok(())
        }
        other => bail!("unknown command {other:?}; expected serve, make-ca, sign or public-key"),
    }
}

async fn serve() -> anyhow::Result<()> {
    let config: Config = serde_json::from_str(&env("CLOVELLY_CONFIG")?).context("CLOVELLY_CONFIG")?;
    if config.collateral_cache_secs > verifier::verifier::COLLATERAL_MAX_AGE_SECS {
        bail!("collateral_cache_secs is over an hour; check 2 would refuse every cached CRL");
    }
    let keys = config
        .release_keys
        .iter()
        .map(|pem| TrustedKey::from_pem(pem))
        .collect::<Result<Vec<_>, _>>()
        .context("release_keys")?;
    let policy = ReleasePolicy::from_jws(&env("CLOVELLY_RELEASE_POLICY")?, &keys)?;
    let sources = HttpSources::new(&policy.endorsements_url, config.collateral_cache_secs)?;
    let port: u16 = std::env::var("PORT").map_or(Ok(8080), |p| p.parse())?;
    let clock = clock()?;
    let releases: Vec<&str> = policy.releases.iter().map(|r| r.id.as_str()).collect();
    println!(
        "{}",
        json!({
            "severity": "INFO",
            "message": format!("verifier {} for env {} on port {port}", env!("CARGO_PKG_VERSION"), config.env),
            "releases": releases,
            "pinned_releases": config.pinned_releases,
            "fragments_url": config.fragments_url.is_some(),
            "rekor_keys": config.rekor_keys.len(),
            "clock_offset_secs": clock.offset_secs(),
            "collateral_cache_secs": config.collateral_cache_secs,
        })
    );
    let fragments_url = config.fragments_url.clone();
    let v = Arc::new(Verifier::new(
        config,
        policy,
        verifier::INTEL_ROOT.to_vec(),
        verifier::GOOGLE_ROOT.to_vec(),
        sources,
        CloudKms::new(Token::Metadata),
    )?);
    // Fragments are in force before the first unlock; then refreshed in the background.
    let http = reqwest::Client::builder().timeout(Duration::from_secs(30)).build()?;
    refresh(&v, &http, fragments_url.as_deref(), clock).await;
    tokio::spawn({
        let v = Arc::clone(&v);
        async move {
            loop {
                tokio::time::sleep(REFRESH).await;
                refresh(&v, &http, fragments_url.as_deref(), clock).await;
            }
        }
    });
    // A batch of final receipts carries their egress logs, which can pass gRPC's 4 MiB
    // default; a refused batch would be retried, and refused, forever.
    tonic::transport::Server::builder()
        .add_service(VerifierServer::new(Service::new(v, clock)).max_decoding_message_size(RECEIPT_BATCH_LIMIT))
        .serve(([0, 0, 0, 0], port).into())
        .await?;
    Ok(())
}

/// The system clock; in a `test-clock` build, moved by CLOVELLY_TEST_CLOCK_OFFSET_SECS.
fn clock() -> anyhow::Result<Clock> {
    #[cfg(feature = "test-clock")]
    if let Ok(secs) = std::env::var("CLOVELLY_TEST_CLOCK_OFFSET_SECS") {
        return Ok(Clock::offset(secs.parse().context("CLOVELLY_TEST_CLOCK_OFFSET_SECS")?));
    }
    Ok(Clock::system())
}

/// Fetches and loads the fragments at `url`, if there is one, and logs each outcome, the
/// releases in force and any expiry warning for a pinned release. A failed fetch keeps
/// the fragments already loaded.
async fn refresh<S: verifier::Sources, K: Kms>(v: &Verifier<S, K>, http: &reqwest::Client, url: Option<&str>, clock: Clock) {
    if let Some(url) = url {
        match fetch_fragments(http, url).await {
            Ok(bundles) => {
                for (i, r) in v.load_fragments(&bundles).into_iter().enumerate() {
                    let line = match r {
                        Ok(id) => json!({ "severity": "INFO", "event": "fragment", "index": i, "result": "applied",
                                          "release": id, "message": format!("fragment {i} applied: {id}") }),
                        Err(e) => json!({ "severity": "WARNING", "event": "fragment", "index": i, "result": "refused",
                                          "error": e.to_string(), "message": format!("fragment {i} refused: {e}") }),
                    };
                    println!("{line}");
                }
            }
            Err(e) => println!(
                "{}",
                json!({ "severity": "ERROR", "event": "fragments-fetch", "error": format!("{e:#}"),
                        "message": "fetching fragments failed; keeping the fragments loaded" })
            ),
        }
    }
    let now = clock.now();
    let policy = v.policy();
    let releases: Vec<_> = policy
        .releases
        .iter()
        .map(|r| json!({ "id": r.id, "open_at": r.open_at(), "valid_until": r.valid_until }))
        .collect();
    println!("{}", json!({ "severity": "INFO", "event": "policy", "now": now, "releases": releases }));
    for w in v.expiry_warnings(now) {
        let what = if w.expired { "has expired" } else { "expires within 7 days" };
        println!(
            "{}",
            json!({ "severity": "WARNING", "event": "release-expiry", "release": w.release, "valid_until": w.valid_until,
                    "expired": w.expired, "now": now,
                    "message": format!("pinned release {} {what} (valid_until {}); pin a newer release", w.release, w.valid_until) })
        );
    }
}

async fn fetch_fragments(http: &reqwest::Client, url: &str) -> anyhow::Result<Vec<FragmentBundle>> {
    let body = http.get(url).send().await?.error_for_status()?.bytes().await?;
    Ok(serde_json::from_slice(&body)?)
}

fn operator_kms() -> anyhow::Result<CloudKms> {
    Ok(CloudKms::new(Token::Fixed(env("CLOVELLY_ACCESS_TOKEN")?)))
}

fn env(name: &str) -> anyhow::Result<String> {
    std::env::var(name).with_context(|| format!("{name} is not set"))
}

fn flag(args: &[String], name: &str) -> anyhow::Result<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
        .with_context(|| format!("{name} is required"))
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    use super::*;

    const INDEX: &[u8] = include_bytes!("../tests/data/fragments-public.json");

    /// Answers one request and returns the URL to send it to.
    fn serve(status: &'static str, content_type: &'static str, body: &'static [u8]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/fragments.json", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            while request.read_line(&mut line).unwrap() > 0 && line != "\r\n" {
                line.clear();
            }
            let head = format!("HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
            stream.write_all(head.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
        });
        url
    }

    fn http() -> reqwest::Client {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        reqwest::Client::new()
    }

    /// raw.githubusercontent.com serves the index as text/plain.
    #[tokio::test]
    async fn the_published_index_is_fetched_as_the_public_repository_serves_it() {
        let url = serve("200 OK", "text/plain; charset=utf-8", INDEX);
        let bundles = fetch_fragments(&http(), &url).await.unwrap();
        assert_eq!(bundles.len(), 2);
    }

    /// Each of these is an error, so `refresh` keeps what is loaded; none may reach
    /// `load_fragments` as an index.
    #[tokio::test]
    async fn a_failed_fetch_is_an_error_and_not_an_empty_index() {
        for (status, body) in [
            ("404 Not Found", &b"404: Not Found"[..]),
            ("429 Too Many Requests", b"[]"),
            ("500 Internal Server Error", b"[]"),
            ("200 OK", b"<!doctype html><title>Unicorn</title>"),
            ("200 OK", &INDEX[..INDEX.len() / 2]),
        ] {
            let url = serve(status, "text/plain", body);
            assert!(fetch_fragments(&http(), &url).await.is_err(), "{status}");
        }
    }
}
