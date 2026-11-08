//! `cell-agent dev-serve` (cargo feature `dev`, never built into an image): the cell API
//! over TLS without attestation, so sandboxes, cgroups and the SDKs can be exercised
//! against runsc on a Linux workstation. It makes its own CA and cell certificate for
//! `--name` and writes the CA to `--ca-out` for the SDK to pin. The policy bundle
//! (`--bundle`, default deny) is signed with a key made here. With `--egress 1`
//! sandboxes get the cell's network: their own namespaces, the nftables rules and the
//! egress proxy (needs nftables and iproute2); without it they have no network.

use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::{Duration, SystemTime};

use anyhow::Context;
use common::proto::cell::cell_server::CellServer;
use common::proto::control::DrainState;
use common::proto::health::health_server::HealthServer;
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair as _};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tonic::transport::Server;

use crate::Flags;
use crate::boot::Unlocked;
use crate::cellapi::CellApi;
use crate::credentials;
use crate::lease::SharedTerms;
use crate::policies::Policies;
use crate::listener::Serving;
use crate::runsc::{Cgroups, NetworkMode, Runsc};
use crate::sandbox::{Identity, Paths, Sandboxes};
use crate::{cgroup, tls};

pub async fn run(args: &[String]) -> anyhow::Result<()> {
    let f = Flags::new(
        args,
        &["--runsc", "--rootfs", "--state", "--port", "--ca-out", "--name", "--cap-secs", "--valid-secs", "--bundle", "--egress", "--proxy-bin"],
    )?;
    let name = f.require("--name")?;
    let port: u16 = f.parse("--port")?.unwrap_or(8443);
    let cap = Duration::from_secs(f.parse("--cap-secs")?.unwrap_or(48 * 3600));
    let valid = Duration::from_secs(f.parse("--valid-secs")?.unwrap_or(30 * 86_400));
    let state = std::path::PathBuf::from(f.require("--state")?);

    let mut ca = CertificateParams::default();
    ca.distinguished_name.push(DnType::CommonName, "clovelly dev environment CA");
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca_key = KeyPair::generate()?;
    let ca_cert = ca.self_signed(&ca_key)?;
    std::fs::write(f.require("--ca-out")?, common::b64::pem("CERTIFICATE", ca_cert.der()))?;
    let issuer = Issuer::new(ca, ca_key);
    let leaf_key = KeyPair::generate()?;
    let leaf = CertificateParams::new(vec![name.to_owned()])?.signed_by(&leaf_key, &issuer)?;
    let mut config = ServerConfig::builder().with_no_client_auth().with_single_cert(
        vec![leaf.der().clone(), CertificateDer::from(ca_cert.der().to_vec())],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
    )?;
    config.alpn_protocols = vec![b"h2".to_vec()];

    let placeable = cgroup::placeable(cgroup::machine()?);
    cgroup::setup(placeable).context("cgroup setup (run privileged with the host cgroup namespace)")?;
    for dir in ["bundles", "pids", "runsc"] {
        std::fs::create_dir_all(state.join(dir))?;
    }
    let (subenv, env) = name
        .strip_suffix(".cells.clovelly.internal")
        .and_then(|r| r.split_once('.'))
        .context("--name is <subenv>.<env>.cells.clovelly.internal")?;
    let egress = match f.get("--egress") {
        Some("1") => {
            let roots = std::fs::read_to_string("/etc/ssl/certs/ca-certificates.crt")?;
            // The proxy binary next to this one (target/<profile>/egress-proxy) unless
            // --proxy-bin names it.
            let bin = match f.get("--proxy-bin") {
                Some(b) => b.into(),
                None => std::env::current_exe()?.with_file_name("egress-proxy"),
            };
            let proxy = egress_proxy::Supervisor::start(egress_proxy::SupervisorConfig {
                bin,
                roots_pem: roots.clone(),
                cell: "dev".into(),
                network: egress_proxy::Network::default(),
                status: Box::new(crate::agent::status),
            })
            .await?;
            let trust = state.join("ca-certificates.crt");
            std::fs::write(&trust, format!("{roots}\n{}", proxy.ca_pem()))?;
            crate::net::setup_cell(egress_proxy::Ports::CELL).await?;
            Some(crate::sandbox::Egress {
                proxy,
                slots: Arc::new(crate::net::Slots::default()),
                trust_store: trust,
                mtu: crate::net::MTU,
            })
        }
        _ => None,
    };
    let network = if egress.is_some() { NetworkMode::Sandbox } else { NetworkMode::None };
    let sandboxes = Sandboxes::new(
        Runsc {
            bin: f.require("--runsc")?.into(),
            state: state.join("runsc"),
            cgroups: Cgroups::Enforce,
            network,
            extra: Vec::new(),
        },
        Paths {
            rootfs: f.require("--rootfs")?.into(),
            bundles: state.join("bundles"),
            binds: Vec::new(),
        },
        placeable,
        Identity {
            // The dev server shares no CPU: its capacity is the machine's placeable size.
            cpu_share: common::sandbox::CpuShare::DEDICATED,
            env: env.parse()?,
            subenv: subenv.parse()?,
            release: "clovelly-dev".parse()?,
            instance_id: 0,
            zone: "dev".parse()?,
            project: "0".into(),
        },
        egress,
        None,
        crate::sandbox::Receipting::local(),
    );
    let now = SystemTime::now();
    let expires = now.duration_since(SystemTime::UNIX_EPOCH)?.as_secs() + valid.as_secs();
    let bundle = f
        .get("--bundle")
        .map(str::to_owned)
        .unwrap_or_else(|| format!(r#"{{"v":1,"env":"{env}","subenv":"{subenv}","version":1,"expires":{expires},"destinations":[]}}"#))
        .into_bytes();
    let signer = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING)?;
    let sig = signer.sign(&aws_lc_rs::rand::SystemRandom::new(), common::jws::signing_input(&bundle).as_bytes())?;
    let policy_sig = common::jws::assemble(&bundle, sig.as_ref(), true)?;
    let policy_key = common::b64::pem("PUBLIC KEY", signer.public_key().as_der()?.as_ref());
    let policies = Policies::new(env.parse()?, subenv.parse()?, placeable, &policy_key);
    policies.offer(&bundle, &policy_sig, "dev")?;
    let lease = Unlocked {
        cell_cert: leaf.der().to_vec(),
        dek: Arc::new(common::dek::Dek::from_bytes([0; 32])),
        policy_bundle: bundle,
        policy_sig,
        policy_key,
        evidence: dev_evidence(env, subenv)?,
        at: now,
        expires: now + Duration::from_secs(3600),
        valid_until: now + valid,
    };
    let terms = SharedTerms::new(&lease, now + cap);
    let (drain, _) = watch::channel(DrainState::Serving);
    let api = CellApi {
        sandboxes,
        terms,
        policies,
        credentials: Arc::new(credentials::Store {
            client: None,
            instance_id: 0,
            zone: "dev".parse()?,
            env: env.parse()?,
            subenv: subenv.parse()?,
        }),
        drain,
        pids: state.join("pids"),
        execs: AtomicU64::new(0),
        templates: None,
    };
    let listener = TcpListener::bind(("0.0.0.0", port)).await?;
    println!("dev-serve {name} on :{port}, placeable {placeable:?}");
    Server::builder()
        .add_service(HealthServer::new(Serving))
        .add_service(CellServer::new(api))
        .serve_with_incoming(tls::incoming(listener, Arc::new(config)))
        .await?;
    Ok(())
}

fn dev_evidence(env: &str, subenv: &str) -> anyhow::Result<common::evidence::Evidence> {
    let key = crate::boot::CellKey::generate();
    Ok(common::evidence::Evidence {
        quote: Vec::new(),
        ccel_table: Vec::new(),
        ccel_log: Vec::new(),
        env: env.parse()?,
        subenv: subenv.parse()?,
        release: "clovelly-dev".parse()?,
        spki: key.spki().clone(),
        nonce: common::evidence::Nonce([0; 32]),
        instance_id: 0,
        zone: "dev".parse()?,
    })
}
