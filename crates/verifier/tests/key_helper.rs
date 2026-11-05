//! The verifier against a key helper: `check-keys` passing and failing for each named reason
//! (phase 8 criterion 1), the loopback rule at start and what a helper may name (2), and
//! `verifier init` making a configuration the verifier starts on (4). Unlocks through a helper
//! need genuine evidence, so criterion 3 and the wrong-key unlock are in the private corpus test.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::proto::verifier::GetCaRequest;
use common::proto::verifier::verifier_client::VerifierClient;
use memory_helper::{Behaviour, Bind, Helper};
use verifier::check_keys::{self, Line, Reason, Suite};
use verifier::init::Vector;
use verifier::keys::{self, KeyError, Keys, Op};

const VERIFIER: &str = env!("CARGO_BIN_EXE_verifier");

fn suite(vector: Option<Vector>) -> Suite {
    Suite { sign_keys: vec!["ca".into(), "policy".into()], dek_key: "dek".into(), vector }
}

fn reasons(lines: &[Line]) -> Vec<Reason> {
    lines.iter().filter_map(|l| l.result.as_ref().err().map(|(r, _)| *r)).collect()
}

/// The suite against a helper behaving as `b`, printing what it says.
async fn against(b: Behaviour) -> Vec<Line> {
    let helper = Helper::start(b);
    let lines = check_keys::run(&helper.url(), &suite(None)).await;
    for line in &lines {
        println!("{line}");
    }
    lines
}

#[tokio::test]
async fn check_keys_passes_against_the_memory_helper() {
    let lines = against(Behaviour::Good).await;
    assert!(check_keys::passed(&lines), "{lines:#?}");
    // Every operation was exercised, on every key.
    for check in ["loopback", "health", "public-key ca", "sign ca", "public-key policy", "sign policy", "encrypt and decrypt dek", "decrypt garbage dek", "unknown key: sign", "unknown key: decrypt", "unknown key: encrypt", "unknown key: public-key"] {
        assert!(lines.iter().any(|l| l.check == check), "{check}");
    }
}

#[tokio::test]
async fn check_keys_fails_a_raw_rs_signature_as_signature_not_der() {
    let lines = against(Behaviour::RawSignature).await;
    assert!(reasons(&lines).contains(&Reason::SignatureNotDer), "{lines:#?}");
}

#[tokio::test]
async fn check_keys_fails_a_signature_from_another_key_as_signature_wrong_key() {
    let lines = against(Behaviour::OtherKey).await;
    assert!(reasons(&lines).contains(&Reason::SignatureWrongKey), "{lines:#?}");
}

#[tokio::test]
async fn check_keys_fails_a_wrong_plaintext_as_decrypt_wrong_plaintext() {
    let lines = against(Behaviour::WrongPlaintext).await;
    assert_eq!(reasons(&lines), [Reason::DecryptWrongPlaintext], "{lines:#?}");
}

#[tokio::test]
async fn check_keys_fails_an_unknown_key_answered_with_anything_but_no_such_key() {
    let lines = against(Behaviour::UnknownKeyDenied).await;
    assert_eq!(reasons(&lines), [Reason::UnknownKeyAnswer; 4], "{lines:#?}");
}

#[tokio::test]
async fn check_keys_fails_garbage_that_decrypts() {
    let lines = against(Behaviour::AcceptsGarbage).await;
    assert_eq!(reasons(&lines), [Reason::DecryptAcceptsGarbage], "{lines:#?}");
}

/// An address that leaves the machine gets no request at all.
#[tokio::test]
async fn check_keys_fails_an_address_off_loopback_as_not_loopback() {
    for url in ["http://10.0.0.1:8200", "https://kms.example.com", "http://localhost:8200"] {
        let lines = check_keys::run(url, &suite(None)).await;
        assert_eq!(reasons(&lines), [Reason::NotLoopback], "{url}: {lines:#?}");
        assert_eq!(lines.len(), 1, "{url}");
    }
}

/// A helper reached on loopback that also listens on every interface.
#[tokio::test]
async fn check_keys_fails_a_helper_that_also_listens_off_loopback_as_not_loopback() {
    let helper = Helper::start_on(Behaviour::Good, Bind::AllInterfaces);
    let lines = check_keys::run(&helper.url(), &suite(None)).await;
    let other = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
    // On a machine with no route there is no other address to catch it on.
    if other.connect("192.0.2.1:9").await.is_ok() {
        assert!(reasons(&lines).contains(&Reason::NotLoopback), "{lines:#?}");
    }
}

/// A running role is refused encrypt, so a stored ciphertext stands in for it, and only then.
#[tokio::test]
async fn check_keys_takes_the_vector_when_the_running_role_is_refused_encrypt() {
    let helper = Helper::start(Behaviour::Good);
    let plaintext = [9u8; 32];
    let vector = Vector {
        ciphertext: common::b64::encode(&helper.client().encrypt("dek", &plaintext).await.unwrap()),
        plaintext: common::b64::encode(&plaintext),
    };
    helper.set(Behaviour::RefusesEncrypt);
    let without = check_keys::run(&helper.url(), &suite(None)).await;
    assert_eq!(reasons(&without), [Reason::EncryptFailed], "{without:#?}");
    let with = check_keys::run(&helper.url(), &suite(Some(vector.clone()))).await;
    assert!(check_keys::passed(&with), "{with:#?}");
    // The vector is really decrypted.
    helper.set(Behaviour::WrongPlaintext);
    let wrong = check_keys::run(&helper.url(), &suite(Some(vector))).await;
    assert_eq!(reasons(&wrong), [Reason::DecryptWrongPlaintext], "{wrong:#?}");
}

/// Each named failure reaches an operator from the binary, with its exit code.
#[test]
fn check_keys_the_command_exits_non_zero_and_names_the_reason() {
    let run = |helper: &Helper| {
        Command::new(VERIFIER)
            .args(["check-keys", &helper.url(), "--sign-key", "ca", "--sign-key", "policy", "--dek-key", "dek"])
            .output()
            .unwrap()
    };
    let good = run(&Helper::start(Behaviour::Good));
    let text = String::from_utf8_lossy(&good.stdout);
    assert!(good.status.success(), "{text}");
    assert!(text.contains("meets the contract"), "{text}");
    let bad = run(&Helper::start(Behaviour::RawSignature));
    let text = String::from_utf8_lossy(&bad.stdout);
    assert!(!bad.status.success(), "{text}");
    assert!(text.contains("FAIL") && text.contains("signature_not_der"), "{text}");
}

/// Every failure a helper can answer comes back as the contract's own error.
#[tokio::test]
async fn the_client_returns_the_contracts_errors_and_gives_up_inside_the_timeout() {
    let helper = Helper::start(Behaviour::Denied);
    let client = helper.client();
    let denied = KeyError::Denied { op: Op::Decrypt, key: "dek".into() };
    assert_eq!(client.decrypt("dek", b"x").await, Err(denied));
    helper.set(Behaviour::Unavailable);
    assert!(matches!(client.sign("ca", &[0; 32]).await, Err(KeyError::Unavailable { .. })));
    helper.set(Behaviour::Good);
    assert!(matches!(client.public_key("nope").await, Err(KeyError::NoSuchKey { .. })));

    helper.set(Behaviour::Hung);
    let started = Instant::now();
    assert!(matches!(client.sign("ca", &[0; 32]).await, Err(KeyError::Unavailable { .. })));
    let waited = started.elapsed();
    assert!(waited >= Duration::from_secs(9) && waited < Duration::from_secs(12), "{waited:?}");
}

/// [`keys::signed`] is what stands between a helper and a certificate.
#[tokio::test]
async fn signed_refuses_a_raw_signature_and_another_keys() {
    let helper = Helper::start(Behaviour::Good);
    let client = helper.client();
    let expected = keys::trusted(&client, "ca").await.unwrap();
    assert!(keys::signed(&client, "ca", b"message", &expected).await.is_ok());
    for bad in [Behaviour::RawSignature, Behaviour::OtherKey] {
        helper.set(bad);
        assert_eq!(
            keys::signed(&client, "ca", b"message", &expected).await,
            Err(KeyError::WrongSignature { key: "ca".into() }),
            "{bad:?}"
        );
    }
}

/// Criterion 2: the first thing `serve` does.
#[test]
fn a_keys_url_that_is_not_loopback_is_refused_at_start() {
    for url in ["http://10.0.0.1:8200", "https://kms.example.com:443", "http://localhost:8200"] {
        let out = Command::new(VERIFIER)
            .arg("serve")
            .env("CLOVELLY_KEYS_URL", url)
            .env("CLOVELLY_CONFIG", "{}")
            .env("CLOVELLY_RELEASE_POLICY", "x")
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{url}");
        assert!(text.contains("is not a key helper on this loopback"), "{url}: {text}");
    }
    let out = Command::new(VERIFIER).arg("serve").env_remove("CLOVELLY_KEYS_URL").output().unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("CLOVELLY_KEYS_URL"));
}

fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            sources(&path, out);
        } else {
            out.push(path);
        }
    }
}

/// Criterion 2: no key manager's endpoint, SDK or credential lookup in the verifier.
#[test]
fn crates_verifier_names_no_key_managers_host() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = vec![crate_dir.join("Cargo.toml")];
    sources(&crate_dir.join("src"), &mut files);
    // Built out of pieces, so this file (which is not scanned anyway) cannot match itself.
    let forbidden = [
        ["cloud", "kms"].concat(),
        ["amazon", "aws"].concat(),
        ["kms.", "aws"].concat(),
        ["aws", "_sdk"].concat(),
        ["aws", "-sdk"].concat(),
        ["aws", "-config"].concat(),
        ["metadata", ".google"].concat(),
        ["169.254", ".169.254"].concat(),
        ["vault", ".azure"].concat(),
        ["key", "vault"].concat(),
        ["ACCESS", "_TOKEN"].concat(),
        ["SECRET", "_ACCESS"].concat(),
    ];
    assert!(files.len() > 15, "{files:?}");
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap_or_default().to_lowercase();
        for word in &forbidden {
            assert!(!text.contains(&word.to_lowercase()), "{} names {word}", file.display());
        }
    }
}

/// Criterion 2: the released binaries are built as the images build them, and neither holds
/// the in-memory keys. Any `LocalKms` or memory helper would have to carry these strings.
#[test]
fn no_released_binary_holds_local_kms_or_the_memory_helper() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let target = workspace.join("target/released-scan");
    for (package, binary) in [("verifier", "verifier"), ("key-helper", "clovelly-keys")] {
        let status = Command::new(env!("CARGO"))
            .args(["build", "-p", package, "--bin", binary, "--target-dir"])
            .arg(&target)
            .current_dir(&workspace)
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "building {binary}");
        let bytes = std::fs::read(target.join("debug").join(binary)).unwrap();
        for marker in [memory_helper::MARKER, "LocalKms", "memory_helper", "memory-helper"] {
            assert!(
                !bytes.windows(marker.len()).any(|w| w == marker.as_bytes()),
                "{binary} holds {marker}"
            );
        }
        // The scan can see: a debug binary names its own types.
        let own = if binary == "verifier" { "HelperClient" } else { "CloudKms" };
        assert!(bytes.windows(own.len()).any(|w| w == own.as_bytes()), "{binary} should name {own}");
    }
}

/// Everything `verifier init` needs: a helper, and a release policy signed by a key we choose.
struct Setup {
    helper: Helper,
    dir: PathBuf,
}

impl Setup {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("clovelly-init-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self { helper: Helper::start(Behaviour::Good), dir }
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut c = Command::new(VERIFIER);
        c.args(args).env("CLOVELLY_KEYS_URL", self.helper.url());
        c
    }

    /// A release policy signed with the helper's `policy` key, standing in for our release key.
    fn release_policy(&self) -> (PathBuf, PathBuf) {
        let key = self.dir.join("release-key.pem");
        let pem = self.command(&["public-key", "--key", "policy"]).output().unwrap();
        assert!(pem.status.success());
        std::fs::write(&key, pem.stdout).unwrap();
        let payload = serde_json::json!({
            "v": 1, "project_number": 123456789012u64, "allowed_zones": ["us-central1-a"], "xfam": 0,
            "mrseam": [], "tee_tcb_svn_floor": "00".repeat(16), "sw_hardening_advisories": [],
            "nonce_ttl_secs": 300, "endorsements_url": "https://example.invalid/", "releases": []
        });
        let mut sign = self.command(&["sign", "--key", "policy"]).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
        std::io::Write::write_all(sign.stdin.as_mut().unwrap(), payload.to_string().as_bytes()).unwrap();
        let signed = sign.wait_with_output().unwrap();
        assert!(signed.status.success());
        let jws = self.dir.join("release-policy-input.jws");
        std::fs::write(&jws, String::from_utf8(signed.stdout).unwrap().trim()).unwrap();
        (key, jws)
    }

    fn init(&self, subenvs: &[&str]) -> std::process::Output {
        let (key, policy) = self.release_policy();
        let out = self.dir.join("out");
        let mut args = vec![
            "init", "--env", "acme", "--ca-key", "ca", "--policy-key", "policy", "--dek-key", "dek",
            "--out", out.to_str().unwrap(), "--release-key", key.to_str().unwrap(),
            "--release-policy", policy.to_str().unwrap(), "--pin", "clovelly-0.4.0",
        ];
        for s in subenvs {
            args.extend(["--subenv", s]);
        }
        self.command(&args).output().unwrap()
    }
}

impl Drop for Setup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Criterion 4: from the memory helper to a verifier that starts and serves the CA, using
/// nothing but the binary.
#[tokio::test]
async fn verifier_init_through_the_memory_helper_makes_a_configuration_the_verifier_starts_on() {
    let setup = Setup::new("starts");
    let out = setup.init(&["main"]);
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert!(out.status.success(), "{text} {}", String::from_utf8_lossy(&out.stderr));
    assert!(text.contains("CLOVELLY_VERIFIER_TOKEN="), "{text}");

    let dir = setup.dir.join("out");
    for file in ["config.json", "verifier.env", "keys.env", "ca.pem", "policy.pub.pem", "release-policy.jws", "check-vector.json"] {
        assert!(dir.join(file).exists(), "{file}");
    }
    // The configuration holds no secret: the token only as its hash, the DEK as ciphertext.
    let token = text.split("CLOVELLY_VERIFIER_TOKEN=").nth(1).unwrap().trim();
    let config = std::fs::read_to_string(dir.join("config.json")).unwrap();
    assert!(!config.contains(token));
    assert!(config.contains(&common::hex(&keys::sha256(token.as_bytes()))));

    // The vector it wrote passes the suite with the running role's rights.
    let vector: Vector = serde_json::from_str(&std::fs::read_to_string(dir.join("check-vector.json")).unwrap()).unwrap();
    setup.helper.set(Behaviour::RefusesEncrypt);
    assert!(check_keys::passed(&check_keys::run(&setup.helper.url(), &suite(Some(vector))).await));
    setup.helper.set(Behaviour::Good);

    // `verifier.env` is what a recipe hands the container, one NAME=value per line. The
    // fragments index is left out so that this test needs no network.
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let mut server = Command::new(VERIFIER);
    server.arg("serve").env("PORT", port.to_string()).stdout(Stdio::null());
    for line in std::fs::read_to_string(dir.join("verifier.env")).unwrap().lines() {
        let (name, value) = line.split_once('=').unwrap();
        if name == "CLOVELLY_CONFIG" {
            let mut c: serde_json::Value = serde_json::from_str(value).unwrap();
            c.as_object_mut().unwrap().remove("fragments_url");
            server.env(name, c.to_string());
        } else {
            server.env(name, value);
        }
    }
    let mut server = server.spawn().unwrap();
    let ca = async {
        for _ in 0..100 {
            if let Ok(mut c) = VerifierClient::connect(format!("http://127.0.0.1:{port}")).await {
                let r = c.get_ca(GetCaRequest { env_id: "acme".into() }).await.unwrap();
                return r.into_inner();
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("the verifier never answered");
    }
    .await;
    let _ = server.kill();
    let _ = server.wait();
    let pem = std::fs::read_to_string(dir.join("ca.pem")).unwrap();
    assert_eq!(common::b64::pem_blocks(&pem, "CERTIFICATE").unwrap().remove(0), ca.ca_cert);
}

/// A second run adds a sub-environment and changes nothing that exists.
#[test]
fn verifier_init_run_again_keeps_what_exists_and_prints_no_new_token() {
    let setup = Setup::new("again");
    assert!(setup.init(&["a"]).status.success());
    let read = || std::fs::read_to_string(setup.dir.join("out/config.json")).unwrap();
    let first: serde_json::Value = serde_json::from_str(&read()).unwrap();
    let out = setup.init(&["a", "b"]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("CLOVELLY_VERIFIER_TOKEN="));
    let second: serde_json::Value = serde_json::from_str(&read()).unwrap();
    assert_eq!(first["subenvs"]["a"], second["subenvs"]["a"]);
    assert_eq!(first["ca"], second["ca"]);
    assert_eq!(first["sdk_token_sha256"], second["sdk_token_sha256"]);
    assert!(second["subenvs"]["b"].is_object());
}

/// A rotation's rewrap: the same plaintext, a new ciphertext.
#[test]
fn verifier_rewrap_keeps_the_plaintext() {
    let setup = Setup::new("rewrap");
    assert!(setup.init(&["a"]).status.success());
    let vector: Vector = serde_json::from_str(&std::fs::read_to_string(setup.dir.join("out/check-vector.json")).unwrap()).unwrap();
    let mut rewrap = setup.command(&["rewrap", "--key", "dek"]).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    std::io::Write::write_all(rewrap.stdin.as_mut().unwrap(), vector.ciphertext.as_bytes()).unwrap();
    let out = rewrap.wait_with_output().unwrap();
    assert!(out.status.success());
    let new = String::from_utf8(out.stdout).unwrap();
    assert_ne!(new.trim(), vector.ciphertext);
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let plain = rt.block_on(setup.helper.client().decrypt("dek", &common::b64::decode(new.trim()).unwrap())).unwrap();
    assert_eq!(common::b64::encode(&plain), vector.plaintext);
}
