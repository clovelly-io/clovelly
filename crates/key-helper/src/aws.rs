//! AWS KMS behind the key helper's interface: copy this for another key manager.
//!
//! A key's name is whatever KMS takes as a `KeyId`: an ARN, a key id or `alias/...`. Credentials
//! come from the SDK's default chain, which is the task's or instance's role when the helper
//! runs and the operator's login when `init` does. There is no access key anywhere in this.
//!
//! **This backend has run on real AWS**; `docs/verifier-aws.md` says how far.

use aws_sdk_kms::Client;
use aws_sdk_kms::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{KeySpec, KeyUsageType, MessageType, SigningAlgorithmSpec, Tag};
use serde_json::json;
use verifier::init::KeyNames;
use verifier::keys::{KeyError, Keys, Op};

use crate::Refused;

/// AWS KMS through the SDK.
#[derive(Debug, Clone)]
pub struct AwsKms {
    client: Client,
}

/// Why setup could not go on.
#[derive(Debug, thiserror::Error)]
pub enum AwsError {
    #[error("{what}: {code}: {message}")]
    Refused { what: String, code: String, message: String },
    #[error("{0} is not an IAM role ARN (arn:aws:iam::ACCOUNT:role/NAME)")]
    NotARole(String),
    #[error("KMS answered with no key id for {0}")]
    NoKeyId(String),
}

fn code<E: ProvideErrorMetadata, R>(e: &SdkError<E, R>) -> (String, String) {
    match e.as_service_error() {
        Some(service) => (service.code().unwrap_or("Unknown").to_owned(), service.message().unwrap_or("").to_owned()),
        None => ("NoAnswer".to_owned(), "no answer from KMS".to_owned()),
    }
}

impl AwsKms {
    /// From the default credential chain and region.
    pub async fn from_environment() -> Self {
        Self { client: Client::new(&aws_config::load_from_env().await) }
    }

    /// With a client configured elsewhere: tests.
    pub fn from_client(client: Client) -> Self {
        Self { client }
    }
}

/// How KMS's answers map onto the contract's three errors.
fn mapped<E: ProvideErrorMetadata, R>(op: Op, key: &str, e: &SdkError<E, R>) -> KeyError {
    let key = key.to_owned();
    match code(e).0.as_str() {
        "NotFoundException" => KeyError::NoSuchKey { op, key },
        "AccessDeniedException" | "DisabledException" | "KMSInvalidStateException" | "InvalidCiphertextException" | "IncorrectKeyException"
        | "InvalidKeyUsageException" | "KeyUnavailableException" => KeyError::Denied { op, key },
        _ => KeyError::Unavailable { op, key },
    }
}

fn missing(op: Op, key: &str) -> KeyError {
    KeyError::Contract { op, key: key.to_owned(), why: "KMS answered with no bytes".into() }
}

impl Keys for AwsKms {
    async fn sign(&self, key: &str, digest: &[u8; 32]) -> Result<Vec<u8>, KeyError> {
        let out = self
            .client
            .sign()
            .key_id(key)
            .message(Blob::new(digest.as_slice()))
            .message_type(MessageType::Digest)
            .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
            .send()
            .await
            .map_err(|e| mapped(Op::Sign, key, &e))?;
        // KMS's ECDSA signatures are already ASN.1 DER.
        Ok(out.signature.ok_or_else(|| missing(Op::Sign, key))?.into_inner())
    }

    async fn decrypt(&self, key: &str, ciphertext: &[u8]) -> Result<Vec<u8>, KeyError> {
        let out = self
            .client
            .decrypt()
            .key_id(key)
            .ciphertext_blob(Blob::new(ciphertext))
            .send()
            .await
            .map_err(|e| mapped(Op::Decrypt, key, &e))?;
        Ok(out.plaintext.ok_or_else(|| missing(Op::Decrypt, key))?.into_inner())
    }

    async fn encrypt(&self, key: &str, plaintext: &[u8]) -> Result<Vec<u8>, KeyError> {
        let out = self
            .client
            .encrypt()
            .key_id(key)
            .plaintext(Blob::new(plaintext))
            .send()
            .await
            .map_err(|e| mapped(Op::Encrypt, key, &e))?;
        Ok(out.ciphertext_blob.ok_or_else(|| missing(Op::Encrypt, key))?.into_inner())
    }

    async fn public_key(&self, key: &str) -> Result<Vec<u8>, KeyError> {
        let out = self.client.get_public_key().key_id(key).send().await.map_err(|e| mapped(Op::PublicKey, key, &e))?;
        // Already a DER SubjectPublicKeyInfo.
        Ok(out.public_key.ok_or_else(|| missing(Op::PublicKey, key))?.into_inner())
    }
}

/// `arn:PARTITION:iam::ACCOUNT:role/NAME`, returning the partition and account.
fn role_parts(arn: &str) -> Result<(&str, &str), AwsError> {
    match arn.split(':').collect::<Vec<_>>().as_slice() {
        ["arn", partition, "iam", "", account, resource] if resource.starts_with("role/") => Ok((partition, account)),
        _ => Err(AwsError::NotARole(arn.to_owned())),
    }
}

/// A key policy: the account's administrators administer it through IAM, as with any KMS
/// key, and `role` may do `actions` and nothing else.
fn key_policy(arn: &str, actions: &[&str]) -> Result<String, AwsError> {
    let (partition, account) = role_parts(arn)?;
    Ok(json!({
        "Version": "2012-10-17",
        "Statement": [
            { "Sid": "Administration", "Effect": "Allow",
              "Principal": { "AWS": format!("arn:{partition}:iam::{account}:root") }, "Action": "kms:*", "Resource": "*" },
            { "Sid": "ClovellyKeyHelper", "Effect": "Allow",
              "Principal": { "AWS": arn }, "Action": actions, "Resource": "*" },
        ],
    })
    .to_string())
}

const SIGNING_ACTIONS: [&str; 2] = ["kms:Sign", "kms:GetPublicKey"];
const DEK_ACTIONS: [&str; 1] = ["kms:Decrypt"];

impl AwsKms {
    /// Makes one key under `alias`, unless the alias already names one, which is left as it
    /// is: re-running `init` changes nothing.
    async fn make_key(&self, alias: &str, env: &str, spec: KeySpec, usage: KeyUsageType, policy: String) -> Result<(), AwsError> {
        match self.client.describe_key().key_id(alias).send().await {
            Ok(_) => return Ok(()),
            Err(e) if code(&e).0 == "NotFoundException" => {}
            Err(e) => {
                let (code, message) = code(&e);
                return Err(AwsError::Refused { what: format!("reading {alias}"), code, message });
            }
        }
        let refused = |what: String, (code, message): (String, String)| AwsError::Refused { what, code, message };
        let tag = Tag::builder().tag_key("clovelly-env").tag_value(env).build().expect("both fields are set");
        // KMS refuses a policy naming a role IAM has not finished making: a stack's role is new.
        let mut attempts = 0;
        let made = loop {
            let result = self
                .client
                .create_key()
                .key_spec(spec.clone())
                .key_usage(usage.clone())
                .policy(&policy)
                .tags(tag.clone())
                .send()
                .await;
            match result {
                Ok(made) => break made,
                Err(e) if code(&e).0 == "MalformedPolicyDocumentException" && attempts < 12 => {
                    attempts += 1;
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
                Err(e) => return Err(refused(format!("creating {alias}"), code(&e))),
            }
        };
        let id = made.key_metadata.map(|m| m.key_id).ok_or_else(|| AwsError::NoKeyId(alias.to_owned()))?;
        self.client
            .create_alias()
            .alias_name(alias)
            .target_key_id(id)
            .send()
            .await
            .map_err(|e| refused(format!("naming {alias}"), code(&e)))?;
        Ok(())
    }

    /// Creates the environment's three keys: the CA and policy keys (EC P-256), the DEK key
    /// (symmetric), named `alias/clovelly-ENV-...`. `role` may sign with the first two and
    /// read their public keys, and decrypt with the third.
    pub async fn make_keys(&self, env: &str, role: &str) -> Result<KeyNames, AwsError> {
        let names = KeyNames {
            ca: format!("alias/clovelly-{env}-env-ca"),
            policy: format!("alias/clovelly-{env}-policy"),
            dek: format!("alias/clovelly-{env}-dek"),
        };
        let signing = key_policy(role, &SIGNING_ACTIONS)?;
        self.make_key(&names.ca, env, KeySpec::EccNistP256, KeyUsageType::SignVerify, signing.clone()).await?;
        self.make_key(&names.policy, env, KeySpec::EccNistP256, KeyUsageType::SignVerify, signing).await?;
        self.make_key(&names.dek, env, KeySpec::SymmetricDefault, KeyUsageType::EncryptDecrypt, key_policy(role, &DEK_ACTIONS)?).await?;
        Ok(names)
    }

    /// Run as the helper's role: tries to create a key, rotate `dek`, disable `sign_key` and
    /// schedule its deletion. Passes only if KMS refuses each. On a role that is too strong
    /// this really does those things, to the keys named: each undoes within 30 days.
    pub async fn check_role(&self, sign_key: &str, dek: &str) -> Vec<Refused> {
        fn refused<T, E: ProvideErrorMetadata, R>(act: &'static str, r: Result<T, SdkError<E, R>>) -> Refused {
            let result = match r {
                Ok(_) => Err("KMS did it".to_owned()),
                Err(e) => match code(&e) {
                    (c, _) if c == "AccessDeniedException" => Ok(()),
                    (c, m) => Err(format!("{c}: {m}")),
                },
            };
            Refused { act, result }
        }
        vec![
            refused("create a key", self.client.create_key().send().await),
            refused("re-key (rotate on demand)", self.client.rotate_key_on_demand().key_id(dek).send().await),
            refused("disable a key", self.client.disable_key().key_id(sign_key).send().await),
            refused(
                "delete (schedule deletion of) a key",
                self.client.schedule_key_deletion().key_id(sign_key).pending_window_in_days(30).send().await,
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_policy_grants_the_role_only_what_it_names() {
        let policy: serde_json::Value = serde_json::from_str(&key_policy("arn:aws:iam::111122223333:role/verifier", &SIGNING_ACTIONS).unwrap()).unwrap();
        let statements = policy["Statement"].as_array().unwrap();
        assert_eq!(statements[0]["Principal"]["AWS"], "arn:aws:iam::111122223333:root");
        assert_eq!(statements[1]["Principal"]["AWS"], "arn:aws:iam::111122223333:role/verifier");
        assert_eq!(statements[1]["Action"], json!(["kms:Sign", "kms:GetPublicKey"]));
    }

    #[test]
    fn only_a_role_arn_is_a_role() {
        assert_eq!(role_parts("arn:aws-cn:iam::1:role/a/b").unwrap(), ("aws-cn", "1"));
        for bad in ["arn:aws:iam::1:user/a", "arn:aws:s3:::b", "role/a", ""] {
            assert!(role_parts(bad).is_err(), "{bad}");
        }
    }
}
