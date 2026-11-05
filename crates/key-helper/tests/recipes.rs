//! Phase 8 criterion 11: nothing we ship holds a private key outside a key manager, and every
//! recipe pins one always-on instance.

use std::path::{Path, PathBuf};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(path: &str) -> String {
    std::fs::read_to_string(root().join(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files_under(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn texts(dir: &str) -> Vec<(String, String)> {
    let mut files = Vec::new();
    files_under(&root().join(dir), &mut files);
    assert!(!files.is_empty(), "{dir}");
    files
        .into_iter()
        .filter_map(|p| std::fs::read_to_string(&p).ok().map(|t| (p.display().to_string(), t)))
        .collect()
}

/// Built out of pieces so that this file, which is under `crates/key-helper`, cannot match itself.
fn word(parts: &[&str]) -> String {
    parts.concat()
}

#[test]
fn no_recipe_or_document_makes_or_holds_a_private_key_outside_a_key_manager() {
    let forbidden = [
        word(&["BEGIN ", "PRIVATE KEY"]),
        word(&["BEGIN EC ", "PRIVATE KEY"]),
        word(&["openssl ", "genpkey"]),
        word(&["openssl ", "ecparam"]),
        word(&["openssl ", "rand"]),
        word(&["AWS_SECRET", "_ACCESS_KEY"]),
        word(&["AWS_ACCESS", "_KEY_ID"]),
        word(&["GOOGLE_APPLICATION", "_CREDENTIALS"]),
        word(&["keys create ", "--iam-account"]),
    ];
    let mut scanned = texts("deploy");
    for doc in ["key-helper", "verifier-deploy", "verifier-gcp", "verifier-aws", "verifier-other", "quickstart", "key-rotation", "offboarding"] {
        scanned.push((format!("docs/{doc}.md"), read(&format!("docs/{doc}.md"))));
    }
    for (path, text) in &scanned {
        for bad in &forbidden {
            assert!(!text.contains(bad.as_str()), "{path} says {bad}");
        }
    }
}

/// A shipped helper has no way to hold or make a private key: it calls a key manager.
#[test]
fn no_shipped_helper_holds_a_private_key() {
    let forbidden = [
        word(&["EcdsaKey", "Pair"]),
        word(&["from_", "pkcs8"]),
        word(&["LessSafe", "Key"]),
        word(&["PRIVATE", " KEY"]),
    ];
    let scanned = texts("crates/key-helper/src");
    assert!(scanned.iter().any(|(p, _)| p.ends_with("gcp.rs")) && scanned.iter().any(|(p, _)| p.ends_with("aws.rs")));
    for (path, text) in &scanned {
        for bad in &forbidden {
            assert!(!text.contains(bad.as_str()), "{path} says {bad}");
        }
    }
    // Nor can it be built with one: the crate's normal dependencies name no signing library.
    let manifest = read("crates/key-helper/Cargo.toml");
    let normal = manifest.split("[dev-dependencies]").next().unwrap();
    assert!(!normal.contains("aws-lc-rs"), "{normal}");
}

/// Google Cloud's and AWS's recipes, and Compose: one instance, kept up.
#[test]
fn every_recipe_pins_one_always_on_instance() {
    let gcp = read("deploy/verifier.sh");
    for needed in ["minScale: \"1\"", "maxScale: \"1\""] {
        assert!(gcp.contains(needed), "deploy/verifier.sh lacks {needed}");
    }
    let aws = read("deploy/verifier-aws.yaml");
    for needed in ["AllowedValues: [0, 1]", "MaximumPercent: 100", "MinimumHealthyPercent: 0", "DesiredCount: !Ref DesiredCount"] {
        assert!(aws.contains(needed), "deploy/verifier-aws.yaml lacks {needed}");
    }
    let compose = read("deploy/compose.yaml");
    assert!(compose.contains("restart: always"), "deploy/compose.yaml");
    assert_eq!(compose.matches("replicas: 1").count(), 2, "deploy/compose.yaml");
    assert!(compose.contains("network_mode: service:verifier"), "deploy/compose.yaml shares loopback");
}

/// The helper is reachable by nothing else in any recipe.
#[test]
fn no_recipe_puts_the_helper_on_a_network() {
    let aws = read("deploy/verifier-aws.yaml");
    assert!(aws.contains("http://127.0.0.1:8200"));
    assert!(!aws.contains("ContainerPort: 8200") && !aws.contains("FromPort: 8200"));
    let compose = read("deploy/compose.yaml");
    assert!(!compose.contains("8200"), "the helper publishes no port");
    let gcp = read("deploy/verifier.sh");
    assert!(gcp.contains("KEYS_URL=http://127.0.0.1:8200"));
}
