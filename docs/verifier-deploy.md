# Deploying the verifier

The verifier is yours. It runs on your platform and decides which cells may serve your environment.
Your environment CA key and data encryption keys stay in your key manager, and we never operate any
of this. What it defends against, and what it does not, is in [threat-model.md](threat-model.md).

You start two published containers next to your key manager: the verifier, and a key helper that is the
only thing that talks to your keys. You need no build tools and no checkout of this repository.

## What your platform must give it

- **An HTTPS address** with a publicly trusted certificate that carries gRPC (HTTP/2 end to end). The
  verifier itself speaks plain HTTP/2 on `PORT` (8080) behind whatever terminates your TLS.
- **Two containers sharing loopback**: a sidecar, a task, a pod, a Compose service on the verifier's
  network namespace.
- **An identity** your key manager will let sign and decrypt with three keys, with no long-lived access
  key where the platform has workload identity.
- **Exactly one instance, always on.** Nonces and the receipt log are in its memory: a second instance
  would not know the first's nonces, and a restart loses receipts not yet read.

Cells reach a verifier outside Google from the addresses in [static-egress-ips.md](static-egress-ips.md),
which you may allowlist. They still authenticate by attestation and by nothing about the network.

## The sequence

The console walks you through this when you create an environment, with your environment id in every
command. Environment and sub-environment ids are lower-case DNS labels: cells of sub-environment `main`
get certificates for `main.MY_ENV.cells.clovelly.internal`.

1. **Choose the images.** Pull by digest. The digests are on the
   [release page](https://github.com/clovelly-io/clovelly/releases) and in the signed payload logged in
   Rekor; [REPRODUCE.md](../REPRODUCE.md) rebuilds both and compares, if you want to check rather than trust:

   ```bash
   export KEYS_IMAGE=ghcr.io/clovelly-io/clovelly-keys@sha256:DIGEST VERIFIER_IMAGE=ghcr.io/clovelly-io/verifier@sha256:DIGEST
   ```

2. **Make the keys and the configuration.** Three keys: `env-ca` signs a certificate for every cell,
   `policy` signs each sub-environment's policy bundle, and `dek` wraps each sub-environment's data
   encryption key at rest. Setup writes everything the verifier needs into a directory, none of it secret,
   and prints your SDK token once:

   - `config.json`, also in `verifier.env` with the release policy: the CA certificate, one wrapped DEK and
     signed default-deny policy bundle per sub-environment, our release key and the index of our releases, the
     release of this image pinned, and the SDK token's hash.
   - `keys.env`: the keys the helper serves.
   - `ca.pem`: your CA certificate, for your SDK. `check-vector.json`: for `verifier check-keys`.

3. **Start the two containers** on your platform, with `verifier.env` and `keys.env`.

4. **Paste the address into the console.** It checks that the verifier answers and serves your CA, then
   creates the environment and shows its first key, once.

For steps 2 and 3, take the recipe for where your keys live. A recipe is a convenience we test, not a
requirement:

- [AWS](verifier-aws.md): AWS KMS, Fargate behind a load balancer on your certificate.
- [Google Cloud](verifier-gcp.md): Cloud KMS, Cloud Run with the helper as a sidecar.
- [Anywhere else](verifier-other.md): any key manager, through a helper you write or copy, on any platform;
  a Compose file for a machine of your own.

## Keys that already exist

`clovelly-keys init` creates keys. If yours exist, run any helper that serves them and use `verifier init`,
the same setup through the helper interface, named in [verifier-other.md](verifier-other.md).

## Accepting releases

`init` pins the release of the image you ran it from: the verifier accepts that release at once and no
other, and you move by pinning the next one. To follow our releases instead, remove `pinned_releases` from
the configuration: the verifier then applies each new release from the index, once its notice window ends
(72 hours, 24 for security releases).

The verifier fetches the index at start-up, before it listens, and every 10 minutes. It trusts the file only as
far as it can check it: a release applies only with a signature from a key in `release_keys` and a Rekor entry
that verifies under the public log's key, which is built in. A verifier that cannot fetch the index, or fetches
one that is stale or damaged, keeps every release it has already applied. Those are held in memory, so a verifier
that restarts during an outage has only your signed release policy until a fetch succeeds. A release past its
`valid_until` is refused even if pinned. Alert on the log event `fragments-fetch`.

## Watching it

- Every unlock attempt is one JSON log line (`event: "unlock"`) with the outcome of each of the ten checks, the
  quote's measurements and the caller's address. A cell is told only the number of the check that refused it. A
  refusal is either a bug or an attack: alert on `result: "refused"`.
- A key helper that fails logs `event: "key-helper"`, with what it answered. The unlock fails closed, and the
  cell asks again. Alert on it: at the end of a lease, a cell that cannot renew ends its sandboxes.
- To revoke the environment, disable the `dek` key. No cell unlocks after that, and running cells keep their keys
  only until their 60-minute lease ends.

## Publishing a policy

A new sub-environment's bundle is default deny and valid for 30 days. To allow a destination or extend it, sign
a new bundle with a higher `version` (the format is in `crates/common/src/bundle.rs`) through your helper,
`verifier sign --key POLICY_KEY --detached < bundle.json`, put both in the configuration and restart the
verifier. Cells take it within 60 seconds. Run `init` again with a new `--subenv` to add a sub-environment: what
exists is kept.

## Updating

Rotating your keys has its own page: [key-rotation.md](key-rotation.md). What to do when you leave:
[offboarding.md](offboarding.md).

- **New verifier version:** the new digests in the same recipe, and pin the new release.
- **New release, not pinned:** nothing to do.
