//! The verifier binary.
//!
//! ```text
//! verifier [serve]                     the gRPC service; reads CLOVELLY_CONFIG,
//!                                      CLOVELLY_RELEASE_POLICY, CLOVELLY_KEYS_URL and PORT
//!                                      (and, built with `test-clock` only,
//!                                      CLOVELLY_TEST_CLOCK_OFFSET_SECS)
//! verifier init --env E --subenv S... --ca-key K --policy-key K --dek-key K [--out DIR]
//!                                      the configuration, for keys that already exist
//!                                      behind any helper (`verifier::init`)
//! verifier check-keys URL --sign-key K... --dek-key K [--vector FILE|JSON]
//!                                      the conformance suite for a helper
//! verifier make-ca --key K --env E [--generation N]   prints a new self-signed CA
//! verifier sign --key K [--detached]   signs stdin as a JWS (ES256)
//! verifier public-key --key K          prints a key's public key (PEM)
//! verifier rewrap --key K              stdin: a wrapped DEK (base64); decrypts and encrypts
//!                                      it again under K's current version
//! ```
//!
//! Every command but `check-keys` reaches the customer's keys through the helper at
//! CLOVELLY_KEYS_URL (`docs/key-helper.md`); the commands other than `serve` default to
//! http://127.0.0.1:8200.

use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use common::release::FragmentBundle;
use serde_json::json;
use verifier::check_keys::{self, Suite};
use verifier::config::Config;
use verifier::init::{self, Args, KeyNames};
use verifier::jws::{self, TrustedKey};
use verifier::keys::{self, HelperClient, Keys, KeysUrl};
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
        "init" => {
            let names = KeyNames { ca: flag(rest, "--ca-key")?, policy: flag(rest, "--policy-key")?, dek: flag(rest, "--dek-key")? };
            let (request, out) = Args::parse(rest)?.request(env!("CARGO_PKG_VERSION"), service::now()).await?;
            let setup = init::init(&operator_keys()?, names, request).await?;
            setup.write(&out)?;
            print!("{}", setup.summary(&out));
            Ok(())
        }
        "check-keys" => check(rest).await,
        "make-ca" => {
            let (key, env) = (flag(rest, "--key")?, flag(rest, "--env")?);
            let generation = init::one(rest, "--generation").map(str::parse).transpose().context("--generation")?;
            let der = verifier::x509::make_ca(&operator_keys()?, &key, &env, generation, service::now()).await?;
            print!("{}", common::b64::pem("CERTIFICATE", &der));
            Ok(())
        }
        "sign" => {
            let key = flag(rest, "--key")?;
            let mut payload = Vec::new();
            std::io::stdin().read_to_end(&mut payload)?;
            let client = operator_keys()?;
            let expected = keys::trusted(&client, &key).await?;
            let sig = keys::signed(&client, &key, jws::signing_input(&payload).as_bytes(), &expected).await?;
            println!("{}", jws::assemble(&payload, &sig, rest.iter().any(|a| a == "--detached"))?);
            Ok(())
        }
        "public-key" => {
            let key = flag(rest, "--key")?;
            print!("{}", common::b64::pem("PUBLIC KEY", &operator_keys()?.public_key(&key).await?));
            Ok(())
        }
        "rewrap" => {
            let key = flag(rest, "--key")?;
            let mut wrapped = String::new();
            std::io::stdin().read_to_string(&mut wrapped)?;
            let client = operator_keys()?;
            let mut plain = client.decrypt(&key, &common::b64::decode(wrapped.trim())?).await?;
            let rewrapped = client.encrypt(&key, &plain).await;
            common::dek::wipe(&mut plain);
            println!("{}", common::b64::encode(&rewrapped?));
            Ok(())
        }
        other => bail!("unknown command {other:?}; expected serve, init, check-keys, make-ca, sign, public-key or rewrap"),
    }
}

/// `check-keys`: prints one line per check and fails if any failed.
async fn check(rest: &[String]) -> anyhow::Result<()> {
    let url = rest.first().filter(|u| !u.starts_with("--")).context("usage: verifier check-keys URL --sign-key K... --dek-key K [--vector FILE|JSON]")?;
    let suite = Suite {
        sign_keys: init::all(rest, "--sign-key").into_iter().map(str::to_owned).collect(),
        dek_key: flag(rest, "--dek-key")?,
        // A file, or the JSON itself where a container has no file to read.
        vector: init::one(rest, "--vector")
            .map(|v| {
                let text = if v.starts_with('{') { v.to_owned() } else { std::fs::read_to_string(v).with_context(|| v.to_owned())? };
                anyhow::Ok(serde_json::from_str(&text).context("--vector")?)
            })
            .transpose()?,
    };
    if suite.sign_keys.is_empty() {
        bail!("at least one --sign-key is required");
    }
    let lines = check_keys::run(url, &suite).await;
    for line in &lines {
        println!("{line}");
    }
    if !check_keys::passed(&lines) {
        bail!("the helper at {url} does not meet the contract (docs/key-helper.md)");
    }
    println!("the helper at {url} meets the contract");
    Ok(())
}

async fn serve() -> anyhow::Result<()> {
    // First, so that an address off loopback stops the verifier whatever else is wrong.
    let helper = HelperClient::new(env("CLOVELLY_KEYS_URL")?.parse::<KeysUrl>()?)?;
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
        helper,
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
async fn refresh<S: verifier::Sources, K: Keys>(v: &Verifier<S, K>, http: &reqwest::Client, url: Option<&str>, clock: Clock) {
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

/// The helper an operator command talks to.
fn operator_keys() -> anyhow::Result<HelperClient> {
    let url = std::env::var("CLOVELLY_KEYS_URL").unwrap_or_else(|_| init::DEFAULT_KEYS_URL.to_owned());
    Ok(HelperClient::new(url.parse::<KeysUrl>()?)?)
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
