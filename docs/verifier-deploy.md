# Deploying the verifier

The verifier is yours: it runs in your Google Cloud project, holds your environment CA
key and your data encryption keys in your Cloud KMS, and decides which cells may serve
your environment. We never operate it. This guide deploys it to Cloud Run in a fresh
project in under an hour. What it defends against, and what it does not, is in
[threat-model.md](threat-model.md).

## What you get

- A Cloud Run service (`verifier`) that cells call at boot: `GetNonce`, `Unlock`, and
  `GetCA` for SDKs (`proto/clovelly/verifier/v1/verifier.proto`).
- A service account, `clovelly-verifier`, that may sign with your CA key and decrypt your
  DEKs, and nothing else.
- A KMS key ring, `clovelly-verifier`, with three keys:
  - `env-ca` (EC P-256, signing): your environment CA. Every cell certificate chains to
    it.
  - `policy` (EC P-256, signing): signs each sub-environment's policy bundle.
  - `dek` (symmetric): wraps each sub-environment's DEK at rest. Disabling or destroying
    this key stops all new unlocks at once.
- `deploy/out/<env>/config.json` and `ca.pem`: the verifier's configuration and your CA
  certificate. Neither holds a secret; DEKs appear only as KMS ciphertext.

## Before you start (10 minutes)

- A Google Cloud project with billing, and an account that can enable APIs, create
  service accounts, KMS keys and Artifact Registry repositories, and deploy Cloud Run.
- On your machine: `gcloud` (logged in), `docker`, `jq`, `openssl`, `git`, and a Rust
  toolchain (`rustup`; the repository pins the version) for the operator commands.
- Nix, or Docker to run Nix in a container (`release/nix.sh` does this), to build the
  verifier reproducibly.
- From us: the release public key you will trust (`PUBLIC KEY` PEM) and the current
  signed release policy (a JWS file). Check both against the published copies:
  `release/release-key.pub` in this repository is our release key.

## 1. Build the verifier image (10–20 minutes the first time)

```bash
git clone https://github.com/clovelly-io/clovelly && cd clovelly
release/nix.sh build-to verifier-image build/verifier-image
```

The image is built hermetically from the pinned inputs; rebuilding the same commit gives
the same image digest, so you can compare it with ours.

## 2. Create the keys and configuration (5 minutes)

```bash
deploy/verifier.sh setup PROJECT REGION ENV SUBENV...
```

For example `deploy/verifier.sh setup acme-verifier us-central1 acme bank-a bank-b`.
Environment and sub-environment ids are lower-case DNS labels; cells of sub-environment
`bank-a` get certificates for `bank-a.acme.cells.clovelly.internal`. For each
sub-environment the script generates a 256-bit DEK, which leaves `openssl` only through
a pipe into KMS. It also signs a default-deny policy bundle with your policy key and
creates your CA certificate with your CA key. It grants the verifier's service account
`roles/cloudkms.signerVerifier` and `roles/cloudkms.cryptoKeyDecrypter` on the key ring,
and nothing at project level.

Then add the release key you trust:

```bash
jq --rawfile k release-key.pem '.release_keys = [$k]' deploy/out/ENV/config.json > c && mv c deploy/out/ENV/config.json
```

To accept a release before its notice window ends (72 hours, 24 for security releases),
add its id to `pinned_releases`. A release past its `valid_until` is refused even if
pinned.

## 3. Deploy (5 minutes)

```bash
deploy/verifier.sh deploy PROJECT REGION ENV verifier build/verifier-image/*.tar.gz release-policy.jws
```

This pushes the image to Artifact Registry and deploys the Cloud Run service, then prints
its URL. Settings, and why:

| Setting | Why |
|---|---|
| `--max-instances=1` | Nonces are held in the instance's memory; one instance keeps them single-use. |
| `--no-invoker-iam-check` | Cells prove themselves by attestation, not by a Google identity. No `allUsers` IAM binding is added. |
| `--use-http2` | The API is gRPC. |
| `collateral_cache_secs` 3600 | Intel collateral, Google's host registry and endorsements are reused for up to an hour; check 2 refuses CRLs fetched longer ago. 0 fetches everything for every unlock. |

## 4. Hand over (5 minutes)

- Give the URL, your environment id and your sub-environment ids to the control plane,
  which passes them to cells as instance metadata (`clovelly-verifier`, `clovelly-env`,
  `clovelly-subenv`). Metadata is untrusted: a wrong URL only means no unlock.
- Give `deploy/out/ENV/ca.pem` (or `GetCA`) to your SDK configuration. The SDK refuses
  any cell whose certificate does not chain to it.

## 5. Try it (5 minutes)

Before the control plane exists, boot one cell by hand in the cell project and watch
it unlock. Use the `prod` image of a release in your policy (a release inside its
notice window must be in `pinned_releases`), the cell shape below (c3-standard-8 with Secure Boot, no vTPM, no integrity
monitoring and no display device), and only
these three metadata keys:

```bash
gcloud compute instances create try-cell --zone=us-central1-a --machine-type=c3-standard-8 \
  --image=IMAGE --network-interface=network=default,nic-type=GVNIC,no-address \
  --service-account=SA --scopes=cloud-platform --maintenance-policy=TERMINATE \
  --max-run-duration=1h --instance-termination-action=DELETE \
  --confidential-compute-type=TDX --shielded-secure-boot --no-shielded-vtpm --no-shielded-integrity-monitoring \
  --metadata='^@^clovelly-env=ENV@clovelly-subenv=SUBENV@clovelly-verifier=URL'
```

Within a minute the verifier logs `unlock accepted` (next step). The `test` image does
not do this on its own: it runs the in-guest harness and unlocks only when the job
tells it to. Delete the cell afterwards.

## 6. Check it (5 minutes)

- Every unlock attempt is one JSON log line (Logs Explorer, `jsonPayload.event="unlock"`)
  with the outcome of each of the ten checks, the quote's measurements and the caller's
  address. A cell is told only the number of the check that refused it.
- A refusal is either a bug or an attack. Alert on `jsonPayload.result="refused"`.
- To revoke the environment, disable the `dek` key version: no cell unlocks after that,
  and running cells keep their keys only until their 60-minute lease ends.

## Updating

- New release policy: redeploy with the new JWS (step 3).
- New verifier version: rebuild (step 1) and redeploy (step 3).
- New sub-environment: run `setup` again with all sub-environments (existing keys and
  DEKs are kept), then redeploy.
