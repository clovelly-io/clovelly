//! `clovelly-keys`: the reference key helpers and their one-command setup.
//!
//! ```text
//! clovelly-keys serve gcp|aws
//!     answers docs/key-helper.md on CLOVELLY_KEYS_LISTEN (default 127.0.0.1:8200) for the
//!     keys in CLOVELLY_KEYS_ALLOW, as the platform's role. CLOVELLY_KMS_ENDPOINT and the
//!     SDK's AWS_ENDPOINT_URL name a regional or private endpoint
//! clovelly-keys init gcp --project P --location L --service-account SA --env E --subenv S...
//!                        [--key-ring R] [--out DIR] [--release-policy FILE] [--pin RELEASE]...
//!     creates the three keys in Cloud KMS, with grants for SA, and writes the configuration.
//!     Uses CLOVELLY_ACCESS_TOKEN (`gcloud auth print-access-token`), else the metadata server
//! clovelly-keys init aws --role ROLE_ARN --env E --subenv S...
//!                        [--out DIR] [--release-policy FILE] [--pin RELEASE]...
//!     the same in AWS KMS, as the login in the SDK's default chain
//! clovelly-keys check-role gcp|aws --sign-key K --dek-key K
//!     run as the helper's role: fails unless the key manager refuses it every administrative act
//! ```

use anyhow::{Context, bail};
use key_helper::Refused;
use key_helper::aws::AwsKms;
use key_helper::gcp::{CloudKms, Place, Token};
use key_helper::server::{self, Allowed, Listen};
use verifier::init::{self, Args, KeyNames};
use verifier::keys::Keys;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("a rustls crypto provider is already installed"))?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>().as_slice() {
        ["serve", "gcp"] => serve(gcp()?).await,
        ["serve", "aws"] => serve(AwsKms::from_environment().await).await,
        ["init", "gcp", ..] => {
            let place = Place {
                project: flag(&args, "--project")?,
                location: flag(&args, "--location")?,
                key_ring: init::one(&args, "--key-ring").unwrap_or("clovelly-verifier").to_owned(),
                env: flag(&args, "--env")?,
                service_account: flag(&args, "--service-account")?,
            };
            let kms = gcp()?;
            let names = kms.make_keys(&place).await?;
            setup(&kms, names, &args).await
        }
        ["init", "aws", ..] => {
            let kms = AwsKms::from_environment().await;
            let names = kms.make_keys(&flag(&args, "--env")?, &flag(&args, "--role")?).await?;
            setup(&kms, names, &args).await
        }
        ["check-role", "gcp", ..] => report(gcp()?.check_role(&flag(&args, "--sign-key")?, &flag(&args, "--dek-key")?).await),
        ["check-role", "aws", ..] => {
            report(AwsKms::from_environment().await.check_role(&flag(&args, "--sign-key")?, &flag(&args, "--dek-key")?).await)
        }
        _ => bail!("usage: clovelly-keys serve gcp|aws | init gcp|aws ... | check-role gcp|aws --sign-key K --dek-key K"),
    }
}

/// An operator's token if one is given, else the platform's service account. A regional or
/// private endpoint for Cloud KMS is named by CLOVELLY_KMS_ENDPOINT.
fn gcp() -> anyhow::Result<CloudKms> {
    let token = std::env::var("CLOVELLY_ACCESS_TOKEN").map_or(Token::Metadata, Token::Fixed);
    Ok(match std::env::var("CLOVELLY_KMS_ENDPOINT") {
        Ok(endpoint) => CloudKms::at(token, &endpoint, key_helper::gcp::METADATA_TOKEN)?,
        Err(_) => CloudKms::new(token)?,
    })
}

async fn serve<K: Keys + 'static>(backend: K) -> anyhow::Result<()> {
    let listen: Listen = match std::env::var("CLOVELLY_KEYS_LISTEN") {
        Ok(addr) => addr.parse()?,
        Err(_) => Listen::default(),
    };
    let allow = std::env::var("CLOVELLY_KEYS_ALLOW").context("CLOVELLY_KEYS_ALLOW names the keys this helper serves, comma-separated")?;
    let names: Vec<&str> = allow.split(',').map(str::trim).filter(|n| !n.is_empty()).collect();
    if names.is_empty() {
        bail!("CLOVELLY_KEYS_ALLOW names no key");
    }
    println!("{}", serde_json::json!({ "severity": "INFO", "message": "key helper up", "listen": format!("{listen:?}"), "keys": names }));
    Ok(server::serve(listen, Allowed::new(backend, names)).await?)
}

async fn setup(keys: &impl Keys, names: KeyNames, args: &[String]) -> anyhow::Result<()> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let (request, out) = Args::parse(args)?.request(env!("CARGO_PKG_VERSION"), now).await?;
    let setup = init::init(keys, names, request).await?;
    setup.write(&out)?;
    print!("{}", setup.summary(&out));
    Ok(())
}

fn report(lines: Vec<Refused>) -> anyhow::Result<()> {
    for line in &lines {
        println!("{line}");
    }
    if lines.iter().all(|l| l.result.is_ok()) {
        println!("the role is refused every administrative act");
        Ok(())
    } else {
        bail!("the role can do more than sign, decrypt and read public keys")
    }
}

fn flag(args: &[String], name: &str) -> anyhow::Result<String> {
    init::one(args, name).map(str::to_owned).with_context(|| format!("{name} is required"))
}
