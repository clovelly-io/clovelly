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
get certificates for `main.MY_ENV.cells.clovelly.internal` and for each cell's own name,
`<instance>.<zone>.main.MY_ENV.cells.clovelly.internal`, which the SDK dials it by.

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

A sub-environment's policy bundle says what its sandboxes may reach and how large they may be. The one `init`
makes is **default deny**: a sandbox reaches nothing on the internet until you allow a destination. It is valid for
30 days. The bundle is JSON, kept with its signature in your configuration (`config.json`, `subenvs.<name>`:
`policy_bundle`, the bundle as a string, and `policy_sig`, its detached signature):

```json
{ "v": 1, "env": "MY_ENV", "subenv": "main", "version": 2, "expires": 1796851052,
  "sandbox": { "default": { "cpu": 1, "memory": 2 }, "max": { "cpu": 7, "memory": 27, "timeout": 86400 } },
  "destinations": [
    { "host": "www.google.com", "port": 443 },
    { "host": "*.example.com", "port": 443 },
    { "host": "api.openai.com", "port": 443, "paths": ["/v1/"],
      "adapter": { "type": "bearer", "header": "authorization", "credential": "openai" } },
    { "host": "pinned.example.net", "port": 443, "passthrough": true } ] }
```

- `v` is 1. `env` and `subenv` must be this environment's and sub-environment's.
- `version` must be higher than the one in force: cells refuse an older bundle.
- `expires` is Unix seconds. A cell refuses an expired bundle for new sandboxes; running ones keep theirs.
- `sandbox`: the defaults and maxima (vCPUs in multiples of 0.5, GiB, seconds up to 86400).
- `destinations`: what is allowed, and nothing else. `host` is a name, an IPv4 address, `*` (any host) or `*.domain`
  (exactly one more label). `port` is required. `paths` (optional) are path prefixes a request must start with.
  `adapter` (optional, not with a wildcard) swaps a sealed credential into the request: `bearer` (in `header`),
  `basic`, or `query` (in `param`), naming the `credential`. `passthrough: true` forwards TLS untouched (no adapter,
  no paths).
- Optional: `cpu_share` (below), `resolvers` (`[{ "ip": "1.1.1.1", "name": "cloudflare-dns.com" }]`, the DNS-over-TLS
  resolvers; the image's pinned set when absent), `templates` (digests a cell pre-pulls).

To publish one: take the bundle from your configuration, change it, raise `version`, and sign it with your policy
key through your helper. On Google Cloud, [verifier-gcp.md](verifier-gcp.md#allowing-a-destination) has every
command. Anywhere else, with your helper on the operator's machine at `127.0.0.1:8200`, jq and the published images:

```bash
jq -r '.subenvs.main.policy_bundle' clovelly-out/MY_ENV/config.json \
  | jq -c '.version += 1 | .destinations += [{"host": "www.google.com", "port": 443}]' | tr -d '\n' > bundle.json
docker run --rm -i --platform linux/amd64 --network container:clovelly-keys-operator -e CLOVELLY_KEYS_URL=http://127.0.0.1:8200 \
  "$VERIFIER_IMAGE" sign --key POLICY_KEY_VERSION --detached < bundle.json | tr -d '\n' > bundle.sig
jq --rawfile b bundle.json --rawfile s bundle.sig '.subenvs.main.policy_bundle = $b | .subenvs.main.policy_sig = $s' \
  clovelly-out/MY_ENV/config.json > config.new && mv config.new clovelly-out/MY_ENV/config.json
```

The bytes signed must be the bytes stored, so keep the bundle on one line with no trailing newline, as above.
`POLICY_KEY_VERSION` is the `-policy` key in `clovelly-out/MY_ENV/keys.env`. Then deploy the verifier again (on Google
Cloud, `./verifier.sh deploy MY_PROJECT us-central1 MY_ENV verifier`). Cells take the new bundle within 60 seconds,
for sandboxes created after that: a running sandbox keeps the bundle it started with. Run `init` again with a new `--subenv` to add a sub-environment: what exists is kept.

### Sharing CPU among a sub-environment's sandboxes

A bundle may set `"cpu_share"` to an integer from 1 to 4 (1 when absent). At a factor F, the sub-environment's
sandboxes share their cell's CPUs: each keeps its CPU request as a hard cap, is guaranteed its request divided by F
when every sandbox is busy, and a cell holds F times as many sandboxes by CPU. Use it for sandboxes that mostly
wait, on a model or the network; leave it at 1 for CPU-bound work. Only your own sandboxes ever share a cell, and
memory is never shared: a sandbox's memory is reserved whatever the factor, so a cell holds no more sandboxes than
its memory allows. Memory binds first at the default size: a `c3-standard-88` places 342 GiB, so it holds 171 sandboxes
of 2 GiB whatever the factor, and sharing pays off only for sandboxes of about 4/F GiB or less (1.3 GiB at 3, 1 GiB
at 4). A sub-environment that shares CPU therefore sets a smaller default size in its bundle (`sandbox.default`, for
example 1 vCPU and 1 GiB). A cell's capacity is the lesser of its CPU times the factor and its memory; an 88 holds 87
sandboxes of 1 vCPU and 1 GiB at 1, 261 at 3 and 342 at 4, and a create it cannot hold is refused (`CAPACITY`) with
the resource that binds named: CPU at 1 and 3, memory at 4.

A cell reads the factor from the bundle it unlocks with and keeps it until it is recycled, so a new factor applies
to cells booted after you publish it; running cells and their sandboxes are unchanged. A bundle with any other
value is refused: at a cell's unlock, the cell creates no sandbox (`POLICY_REFUSED`, naming `cpu_share`) until it
gets a bundle it accepts; on a later refresh, the cell logs the refusal and keeps the bundle in force. Each
sandbox's receipt says the factor it ran under (`cpu_share`, 1 for dedicated CPU), and so does
`clovelly-receipt verify`.

## Updating

Rotating your keys has its own page: [key-rotation.md](key-rotation.md). What to do when you leave:
[offboarding.md](offboarding.md).

- **New verifier version:** the new digests in the same recipe, and pin the new release.
- **New release, not pinned:** nothing to do.
