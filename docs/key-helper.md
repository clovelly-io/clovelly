# The key helper

The verifier holds no key-manager code. Everything it needs from whatever holds your keys
goes through one small HTTP interface, served by a second container beside it: the key helper.
This page is the whole contract. You can write a helper for any key manager from this page and
the reference code, in any language, and `verifier check-keys` tells you whether it is right.

We ship two reference helpers in the `clovelly-keys` image, for Google Cloud KMS and AWS KMS.
They are examples: `crates/key-helper/src/gcp.rs` and `aws.rs` are each small enough to read in
one sitting and are what you copy for anything else. `crates/key-helper/src/server.rs` is the HTTP
side, which any Rust helper can reuse as it is.

## Where it runs

The helper shares the verifier's loopback and nothing else can reach it: a Cloud Run sidecar, a
container in the same ECS task or Kubernetes pod, a Compose service on the verifier's network
namespace. The verifier finds it through `CLOVELLY_KEYS_URL`, for example
`http://127.0.0.1:8200`.

- **Loopback only.** Whoever can reach the helper can sign as your environment CA and decrypt your
  data keys, so the interface has no authentication and is never on a network. The verifier refuses
  to start if `CLOVELLY_KEYS_URL` is not a loopback address (`127.0.0.0/8` or `[::1]`, written as a
  number, with no path, user or query). A helper must bind a loopback address only.
- **If your keys sit behind a remote service,** the helper is the thing that calls it. The helper's
  own credentials to that service are the helper's business and should come from the platform's
  workload identity, not from a long-lived key.
- **Keys stay in a key manager.** A helper that holds a private key itself, in a file, an environment
  variable or its memory, works: the verifier cannot tell. It also throws away what the key manager
  gives you (revocation, an audit log, a key that cannot be copied), so whoever writes one has chosen
  a weaker verifier than ours. We do not ship one.

## Requests

HTTP/1.1, JSON bodies, `Content-Type: application/json`. All binary values are base64 in the standard
alphabet with padding (RFC 4648 section 4). A request has the fields shown and no others.

A key is named by a string the verifier passes through and never parses: whatever your helper
understands, up to 1024 bytes. A name reaches the verifier through its configuration, where you (or
`verifier init`) put it. The reference helpers take the key manager's own name for a key: a Cloud KMS
resource path, an AWS key ARN or alias.

| Operation | Request | Success: `200` |
|---|---|---|
| **Sign** | `POST /v1/sign` `{"key": "K", "digest": "<base64>"}` | `{"signature": "<base64>"}` |
| **Decrypt** | `POST /v1/decrypt` `{"key": "K", "ciphertext": "<base64>"}` | `{"plaintext": "<base64>"}` |
| **Encrypt** | `POST /v1/encrypt` `{"key": "K", "plaintext": "<base64>"}` | `{"ciphertext": "<base64>"}` |
| **Public key** | `POST /v1/public-key` `{"key": "K"}` | `{"public_key": "<base64>"}` |
| **Health** | `GET /v1/health` | `{"status": "ok"}` |

### Sign

`digest` is exactly 32 bytes: a SHA-256 digest the verifier computed. The digest goes in, not the
message, because that is the one form every key manager signs. Do not hash it again.

`signature` is an ECDSA P-256 signature over that digest, encoded as ASN.1 DER
(`SEQUENCE { r INTEGER, s INTEGER }`): 70 to 72 bytes in almost every case. It is not the raw 64 bytes
of `r||s` that some key managers return and JWS uses; a helper in front of one of those re-encodes it.

The verifier checks every signature under that key's public key before it uses it. For the environment
CA the public key is the one in your CA certificate, so a helper that answers with another key's
signature is refused, and the unlock with it.

### Decrypt and encrypt

`ciphertext` is whatever your key manager produced, opaque to the verifier. `decrypt` returns exactly
the bytes that `encrypt` was given under the same key. Plaintexts are at most 4096 bytes; the verifier's
are 32-byte data keys.

The verifier decrypts on every unlock, renewal and seal. It encrypts only in `verifier init` and
`verifier rewrap`, so the identity a running helper uses should be refused `encrypt`, and answers
`denied`. See "Checking a helper" for what that means for the suite.

### Public key

`public_key` is a DER SubjectPublicKeyInfo for a P-256 key. For a key manager that versions its keys,
the name says which version; the reference Google helper is given a name ending
`/cryptoKeyVersions/N` for this and for sign. The verifier only asks this of signing keys.

### Health

Answers whether the helper's process is up. It must answer quickly and must not depend on the key
manager, so that `unavailable` from an operation and a helper that is not running stay two different
things to whoever is reading the logs.

## Errors

Any other answer than `200` carries this body, with the status in the table:

```json
{"error": "denied", "message": "for a person reading a log; optional"}
```

| `error` | Status | What it must mean |
|---|---|---|
| `no_such_key` | 404 | This name is not a key this helper serves. Not "it might exist": a helper that cannot tell should hold a list of the keys it serves and answer this for every other name, as the reference helpers do (`CLOVELLY_KEYS_ALLOW`), because some key managers answer a name you may not use and a name that does not exist with the same refusal. |
| `denied` | 403 | The key exists and the key manager refuses this: the key or its version is disabled or destroyed, this identity lacks the permission, or a ciphertext does not open under this key. Revoking a key must produce this. |
| `unavailable` | 503 | The answer is not known: the key manager timed out, throttled or failed. |

A helper may answer a request that does not parse with status `400` and any body; the verifier sends
only well-formed requests.

## What the verifier does with an answer

- **Every request has 10 seconds,** from connection to the last byte of the body. The verifier sends it
  once. A helper that wants to retry does so inside the 10 seconds.
- **Any failure fails the unlock closed**: `no_such_key`, `denied`, `unavailable`, a refused connection,
  a timeout, an answer it cannot parse, a signature that does not verify. The cell gets gRPC
  `UNAVAILABLE`, no certificate and no key, and asks again. The next attempt after your helper is back
  succeeds; the verifier keeps no memory of the failure.
- **Redirects and proxies are not followed.** `HTTP_PROXY` and friends do not apply to this address, and
  a `3xx` is a failure.

Nothing a helper must do lives only in the verifier: this list is the verifier's whole behaviour towards
it, and `crates/verifier/src/keys/` is its code.

## Checking a helper

```bash
verifier check-keys http://127.0.0.1:8200 --sign-key CA_KEY --sign-key POLICY_KEY --dek-key DEK_KEY
```

Run it where it shares the helper's loopback. Each check prints one line and the command exits non-zero
if any fails, with the reason's name:

| Reason | What the helper did |
|---|---|
| `not_loopback` | The URL is not a loopback address, or the helper also answers on this machine's other address. |
| `health_failed` | `GET /v1/health` did not answer `{"status":"ok"}`. |
| `public_key_invalid` | A signing key's public key is not a DER SubjectPublicKeyInfo for P-256. |
| `signature_not_der` | A signature is not ASN.1 DER: most often the raw 64 bytes of `r||s`. |
| `signature_wrong_key` | A signature is DER, and does not verify under that key's public key. |
| `encrypt_failed` | Encrypt failed, with no `--vector` to stand in for it. |
| `decrypt_wrong_plaintext` | Decrypt returned bytes other than the ones encrypted. |
| `decrypt_accepts_garbage` | A ciphertext that was never encrypted answered `200`, or anything but `denied`. |
| `unknown_key_answer` | A key that does not exist answered with anything but `no_such_key`, on any operation. |
| `bad_error_body` | An error came with a status and `error` that disagree with the table above. |
| `operation_failed` | An operation answered `denied` or `unavailable` where it should have worked; the line says which. |

**The running identity is refused encrypt.** `check-keys` needs a known plaintext to tell a right
decrypt from a wrong one. `clovelly-keys init` and `verifier init` write `check-vector.json`, a
ciphertext of random bytes that are no one's secret, with its plaintext. Passed as `--vector
check-vector.json`, or as the JSON itself where a container has no file to read, it stands in for
encrypt when encrypt answers `denied`.

## The reference helpers

```bash
clovelly-keys serve gcp      # Cloud KMS, as the platform's service account, from the metadata server
clovelly-keys serve aws      # AWS KMS, as the task's or instance's role
```

`CLOVELLY_KEYS_ALLOW` lists the keys it serves, comma-separated; `init` writes it in `keys.env`.
`CLOVELLY_KEYS_LISTEN` is the address, `127.0.0.1:8200` by default, and anything not on loopback is
refused at start.

`clovelly-keys check-role gcp|aws --sign-key K --dek-key K` runs as the helper's running identity and
tries to create, delete, disable and re-key: it passes only if the key manager refuses all of them.
