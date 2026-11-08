# @clovelly/sdk

TypeScript client for the confidential sandbox service. It asks the control plane where to
put a sandbox, then talks to that cell directly over gRPC and TLS pinned to your
environment CA. The control plane never sees content or access keys. The client is thin
and written by hand over the protocol in `proto/` (SPEC.md, "The SDK").

Sandboxes, exec, files, credentials (phase 3), and from phase 4 encrypted templates,
volumes, signed receipts and the customer's receipt log. The SDK never holds a DEK.

## Install

Node 20.19 or later.

```sh
cd sdks/typescript
npm install
npm run build        # tsc: dist/src (the package), dist/test, dist/examples
npm test             # node:test, against in-process fake servers
npm run licences     # node scripts/check-licences.mjs
```

The package is self-contained: `proto/` is a committed copy of the repository's protos,
loaded at runtime. After changing a proto in the repository, run `npm run protos` and
commit both copies.

## API

```ts
import { Environment } from "@clovelly/sdk";

const env = new Environment({ verifierUrl, envId: "staging", caBundle: "env-ca.pem" });

const sb = await env.sandbox("bank-a", { cpu: 1, memory: 2, timeout: 900 });
const r = await sb.exec("python3 run.py", { stdin: input, env: { MODE: "batch" } });
await sb.files.write("/work/input.json", data);
const out = await sb.files.read("/work/out.json");
const receipt = await sb.close();

const again = await env.reconnect(sb.id, sb.key, { subenv: "bank-a" });   // from any process
env.close();
```

`new Environment({ verifierUrl, envId, caBundle, apiUrl?, apiToken?, apiCa?, verifierToken?, verifierCa? })`

- `caBundle`: the environment CA, as PEM (string or Buffer) or a path to a PEM file. It is
  the only trust anchor for cells.
- `envId`: a DNS label. It names the cells: each cell's certificate carries
  `<subenv>.<envId>.cells.clovelly.internal` and the cell's own
  `<instance>.<zone>.<subenv>.<envId>.cells.clovelly.internal`.
- `verifierUrl`: your verifier, `https://host[:port]`. The SDK calls it to seal credentials
  and template keys and to read the receipt log, always with the SDK token
  `verifierToken`. `verifierCa` (PEM or a path) replaces the system roots for its
  certificate.
- `apiUrl`, `apiToken`, `apiCa`: the control plane. These are service settings, not trust
  inputs. See the environment variables below.

`env.sandbox(subenv, { template?, volume?, volumeGib?, timeout?, cpu?, memory?, command?, env? })`
resolves to a `Sandbox`.

- `cpu`: vCPUs in multiples of 0.5. `memory`: whole GiB. `timeout`: whole seconds, 1 to
  86400. Leave any of them out to get the sub-environment's default.
- `command`: the sandbox's main process, as a string (run under `/bin/sh -c`) or argv.
  When it exits, the sandbox ends. Without one, the sandbox lives until `close()` or its
  timeout. `env` is that process's environment.
- `template`, `volume` and `volumeGib`: see [Templates](#templates) and [Volumes](#volumes).
  `policy` is typed `never` and rejected at runtime: a sub-environment has one policy bundle.
- A cell that refuses with `CAPACITY`, `CROSSES_CELL_END`, `CROSSES_RELEASE_EXPIRY`,
  `DRAINING` or `REVOKED` is added to `avoidCells` and the sandbox is placed again, at most
  3 placements in all.
- A placement must be for this environment and `subenv`, with a 32-hex sandbox id, a
  `host:port` cell address (the region's relay) and a cell name under that sub-environment.
  Otherwise the SDK throws `ProtocolError`.
- Every placement that does not become the sandbox is released with `ReleaseSandbox`, best
  effort. That covers a cell refusal, a failed verification and any other error before the
  sandbox exists.

`env.reconnect(sandboxId, key, { subenv? })` reopens an existing sandbox. `LocateSandbox`
names the cell, and `GetReceipt` on that cell confirms the key. If you pass `subenv`, the
cell is verified for that sub-environment, and a placement naming another environment or
sub-environment throws `ProtocolError`. If you leave `subenv` out, the sub-environment the
control plane reports is used.

`Sandbox` has these readonly fields:

| Field | Meaning |
|---|---|
| `id` | 32 lowercase hex characters (`SandboxId`) |
| `key` | Access key, 64 hex characters. Keep it secret. With `id`, it is all `reconnect` needs. |
| `cellId` | The cell holding the sandbox |
| `cellAddress` | That cell's address |
| `subenv` | The sub-environment |
| `cold` | A cell had to be booted for this sandbox |
| `cpu`, `memory`, `timeout` | What was placed, defaults filled in |
| `timings` | `placeMs`, `connectMs` (0 when the cell's connection was already verified), `createMs` and `runscMs` (runsc create and start, measured in the cell). Place, connect and create times are summed over re-placements. |

Methods:

- `exec(command, { stdin?, env?, cwd?, timeout? })` runs a command: a string under
  `/bin/sh -c`, or an array as argv. stdin is sent in 64 KiB chunks, then EOF. It resolves
  to `{ exitCode, stdout, stderr, firstExecMs, firstStdoutAt, sandboxEnded }`.
  `firstExecMs` is set only on the sandbox's first exec: the cell's time from runsc create
  to the first stdout byte. `firstStdoutAt` is the `performance.now()` at which the first
  stdout chunk arrived. `sandboxEnded` is set (for example `"revoked"`) if the sandbox
  itself ended while the command ran.
- `files.write(path, data)` and `files.read(path)`. The parent directory must exist. A
  missing file throws `FileNotFound`.
- `receipt()` returns the sandbox's signed `Receipt` (see [Receipts](#receipts)): interim
  while it runs, final once it has ended.
- `close()` kills the sandbox and returns its final receipt (the one it ended with if it had
  already ended). It then calls `ReleaseSandbox` on the control plane, best effort.

`env.cell(address, name, subenv)` returns a low-level `Cell` for tests that talk to a cell
directly, by its region's relay address and its own name (`sandbox.cellAddress` and
`sandbox.cellName`). It has `verify()` and the raw RPCs: `createSandbox`, `exec`, `readFile`,
`writeFile`, `kill` and `getReceipt`. Each raw RPC verifies the cell first.

## Environment variables

| Variable | Used for |
|---|---|
| `CLOVELLY_API_URL` | Default `apiUrl`: `host:port` or `https://host:port` |
| `CLOVELLY_API_TOKEN` | Default `apiToken`. It is sent as `authorization: Bearer <token>` on every control-plane call. |
| `CLOVELLY_API_CA` | Default `apiCa`: PEM or a path. If unset, the system roots are used. |
| `CLOVELLY_VERIFIER_TOKEN` | Default `verifierToken`: the verifier's SDK token, needed by `putCredential`, `uploadTemplate`, `receipts` and `egressLog`. |
| `CLOVELLY_VERIFIER_CA` | Default `verifierCa`: PEM or a path. If unset, the system roots are used. |

`examples/smoke.ts` (`npm run smoke` after a build) also reads `CLOVELLY_VERIFIER_URL`,
`CLOVELLY_ENV_ID`, `CLOVELLY_CA_BUNDLE` (a path), `CLOVELLY_SUBENV` and, optionally, `CLOVELLY_SMOKE_FILE`
(default `/tmp/clovelly-smoke.txt`). It runs phase 2 criterion 1: create a sandbox, run
`python3 -c 'print(6*7)'`, write and read back a file, then close. It prints one JSON object
with each step's result and time, and exits non-zero on any failure.

## Regions

```ts
const pool = await env.putPool("bank-a", { region: "europe-west4", minWarmPerZone: 0, idleWindowSecs: 0 });
pool.region; pool.zones; // "europe-west4", ["europe-west4-a", ...]
```

A sub-environment's cells run in the region its pool names, one of the published list
(`docs/regions.md`); another name rejects with `UnknownRegion`, whose `regions` is the list. The
region is set once: another region is another sub-environment. The control plane uses every
approved zone of it and hides a zone that is out of machines. When every zone of the region is
out and no cell can take the sandbox, `env.sandbox()` rejects with `NoCapacity` within seconds,
billing nothing, with `region` and `retryAfter`. The SDK never queues it or tries another region:
that choice is yours, by creating the sandbox in a sub-environment elsewhere.

## Credentials

```ts
await env.putCredential("bank-a", "openai", apiKey, { adapter: "bearer", destination: "api.openai.com" });
const sb = await env.sandbox("bank-a");
await sb.exec("python3 call.py", { env: { OPENAI_API_KEY: sb.cred("openai") } });
```

`putCredential` has the customer's own verifier seal the secret under the sub-environment's
DEK, bound to the name, adapter type and one destination host; the control plane stores only
the ciphertext. Sandboxes see the placeholder `clovelly://cred/<name>` (`sb.cred(name)`), which
the cell's egress proxy replaces only in requests to that destination. A cell refuses a
create with `PolicyRefused` while it holds no acceptable policy bundle, and with
`CredentialUnavailable` if a credential the policy names cannot be opened.

## Templates

```ts
const template = await env.uploadTemplate("bank-a", "analyst-v3", "analyst-v3.tar.gz");
// { name, digest, ciphertextBytes, plaintextBytes, parts }
const sb = await env.sandbox("bank-a", { template });   // or template.digest, or "analyst-v3"
await env.template("bank-a", "analyst-v3");             // Control.GetTemplate
```

A template is a sandbox root given as a `.tar.gz`, stored per sub-environment under a name
(1-64 of a-z, 0-9, `_`, `-`, `.`; a later upload of the same name replaces it). Its digest is
the SHA-256 of the file, lowercase hex (`TemplateDigest`), and is what `CreateSandbox` and the
sandbox's receipt (`sandbox.template_digest`) name.

`uploadTemplate` reads the file twice, 1 MiB at a time, and never holds it in memory: once
for the digest, then to encrypt and stream it. The customer's verifier (`SealTemplateKey`,
with the SDK token) issues a fresh 256-bit key for that digest with the same key sealed under
the sub-environment DEK. The SDK encrypts with AES-256-GCM (`node:crypto`) in
`crates/common/src/template.rs`'s chunked format, byte for byte (a test checks the Rust
encryptor's output hash), and streams `PutTemplate`: a header with the digest, sealed key and
size, then the ciphertext in messages just under 4 MiB. The control plane stores ciphertext
it cannot open; only a cell of the sub-environment can. The key is zeroed once the stream
ends. A file that changes between the two reads cancels the upload with `InvalidRequest`
before its last chunk is sent.

`sandbox({ template })` takes a `Template`, a digest or a name. A name is resolved by the
control plane (`GetTemplate`; `NoSuchTemplate` if there is none) before placing; pass the
`Template` or its digest to pin the exact content. The cell checks the decrypted template
against the digest and refuses with `TemplateUnavailable` if it cannot fetch, open or match it.

## Volumes

```ts
const sb = await env.sandbox("bank-a", { volume: "work", volumeGib: 5 });
```

`volume` names a persistent volume of the sub-environment (1-64 of a-z, 0-9, `_`, `-`),
mounted at `/volume`. It is created on first use with `volumeGib` GiB (1 to 20, default 1);
`volumeGib` without `volume` is an `InvalidRequest`. One sandbox mounts a volume at a time: a
second create is refused with `VolumeBusy`, and the SDK does not place it again. A volume of
another sub-environment or environment does not open (`VolumeUnreadable`); unreachable blocks
are `VolumeUnavailable`.

## Receipts

`sb.close()`, `sb.receipt()` and the low-level `cell.kill` and `cell.getReceipt` return a
`Receipt`:

| Field | Meaning |
|---|---|
| `json` | The receipt in JCS canonical form: exactly the signed bytes |
| `signature` | ECDSA P-256 with SHA-256 over `json` by the cell key, `r \|\| s` (64 bytes) |
| `cellCert` | The signing cell's certificate (DER), which chains to the environment CA |
| `final` | The sandbox has ended; no later receipt will follow |
| `exitKind` | `"running"` while it runs, then `"exited"`, `"killed"`, `"timeout"`, ... |
| `doc` | `json` parsed (`data` is the same object, deprecated) |

The SDK does not verify receipts. The public receipt tool does, from the receipt, the cell
certificate's chain to the environment CA and the published measurement set.

The cell also appends every receipt to the customer's log at their verifier, which keeps the
latest record per sandbox. Read it with the SDK token:

```ts
const records = await env.receipts({ subenv: "bank-a", sandboxIds: [sb.id] });   // both optional
// each: { json, signature, cellCert, final, receivedUnixMs, records, finals, doc }
const log = await env.egressLog(sb.id);   // GetEgressLog: { sandboxId, lines, sha256 }
log.matches(records[0]);                  // true: its egress_log_hash is this log's hash
```

`egressLog` checks that SHA-256 over every line followed by a newline is the `sha256` the
verifier returned, and throws `EgressLogMismatch` otherwise. `log.matches(receipt)` (a
`Receipt` or a `LoggedReceipt`) checks the receipt is for that sandbox and its
`egress_log_hash` is the log's hash; a receipt without one (no egress) matches only an empty
log. `egressLogSha256(lines)` computes the hash.

## Connection rules

These are enforced and cannot be turned off.

- Each cell has one gRPC channel, cached by address and expected name and shared by every
  sandbox on that cell. gRPC multiplexes their streams.
- The channel dials the region's relay with `grpc.credentials.createSsl(envCa)` and
  `grpc.ssl_target_name_override` and `grpc.default_authority` set to the cell's own name,
  `<instance>.<zone>.<subenv>.<envId>.cells.clovelly.internal`. The relay routes by that name
  and terminates nothing. The SDK takes `subenv` from the caller and refuses a placement for
  any other, or whose cell name is not under it. The one exception is `reconnect` called
  without `subenv`, which uses the sub-environment the control plane reports for the
  sandbox. The cell's certificate must chain to the environment CA and carry that name under
  standard hostname verification, so a connection delivered to any other cell is refused.
  There are no custom certificate callbacks (SPEC decision 2).
- Before any RPC that carries data, the SDK sends a `grpc.health.v1.Health/Check` probe with
  an empty request and a 15 s deadline, and retries it while connecting. gRPC sends even
  this probe only after the TLS handshake has verified the certificate. If the cell is
  refused, nothing beyond the handshake reaches it.
- If the handshake fails, the SDK throws `CellVerificationError` with `kind` set to
  `untrusted_certificate` (self-signed, another CA, or expired), `name_mismatch` (the SAN
  names another environment or sub-environment) or `handshake` (any other TLS failure).
  The refused channel is closed and dropped from the cache.

## Errors

Every error is a `ClovellyError` with these fields:

- `reason`: the `clovelly-error` trailer, or undefined.
- `code`: the gRPC status code.
- `details`: the status message.

Each `ErrorReason` in `cell.proto` and `control.proto` has its own subclass:

| Reason | Class |
|---|---|
| `INVALID_SANDBOX_ID` | `InvalidSandboxId` |
| `INVALID_REQUEST` | `InvalidRequest` (also raised by the SDK's own argument checks) |
| `NO_SUCH_SANDBOX` | `SandboxNotFound` |
| `PERMISSION` | `PermissionDenied` |
| `SANDBOX_EXISTS` | `SandboxExists` |
| `CAPACITY` | `CapacityError` |
| `ABOVE_POLICY_MAXIMUM` | `AbovePolicyMaximum` (from a cell or the control plane) |
| `CROSSES_CELL_END` | `CrossesCellEnd` |
| `CROSSES_RELEASE_EXPIRY` | `CrossesReleaseExpiry` |
| `DRAINING` | `CellDraining` |
| `REVOKED` | `CellRevoked` |
| `SANDBOX_ENDED` | `SandboxEnded` |
| `NO_SUCH_FILE` | `FileNotFound` |
| `RUNTIME` | `RuntimeFailure` |
| `UNAUTHENTICATED` | `Unauthenticated` |
| `NO_SUCH_ENVIRONMENT` | `NoSuchEnvironment` |
| `NO_SUCH_SUBENVIRONMENT` | `NoSuchSubenvironment` |
| `NO_SUCH_POOL` | `NoSuchPool` |
| `NO_SUCH_CELL` | `NoSuchCell` |
| `NO_CELL_CAN_HOLD` | `NoCellCanHold` |
| `NO_CELL_READY` | `NoCellReady` |
| `CELL_CREATE_FAILED` | `CellCreateFailed` |
| `QUOTA_EXCEEDED` | `QuotaExceeded` |
| `NO_CAPACITY` | `NoCapacity` (`region`, `retryAfter` seconds) |
| `UNKNOWN_REGION` | `UnknownRegion` (`regions`, the published list) |
| `BELOW_MINIMUM_TOP_UP` | `InvalidRequest` (credit is bought in the console) |
| `POLICY_REFUSED` | `PolicyRefused` |
| `CREDENTIAL_UNAVAILABLE` | `CredentialUnavailable` |
| `STORAGE` | `StorageUnavailable` |
| `TEMPLATE_UNAVAILABLE` | `TemplateUnavailable` |
| `NO_SUCH_TEMPLATE` | `NoSuchTemplate` |
| `VOLUME_BUSY` | `VolumeBusy` (from a cell or the control plane) |
| `VOLUME_UNREADABLE` | `VolumeUnreadable` |
| `VOLUME_UNAVAILABLE` | `VolumeUnavailable` |

More classes have no reason:

- `CellVerificationError`: the cell was refused (see above).
- `ProtocolError`: a server sent something the protocol does not allow. Examples: a
  malformed placement, a placement for another environment or sub-environment, an Exec
  stream without an exit message, a receipt that is not JSON.
- `CellUnavailable`: the cell is unreachable or not serving.
- `ControlPlaneUnavailable`: the control plane is unreachable or timed out.
- `EgressLogMismatch` (a `ProtocolError`): an egress log whose lines do not hash to the
  SHA-256 the verifier sent with it.
- `VerifierUnavailable`: the verifier is unreachable or did not answer. The verifier sends no
  reason trailer: UNAUTHENTICATED is `Unauthenticated`, INVALID_ARGUMENT `InvalidRequest`,
  NOT_FOUND `NoSuchSubenvironment` (`SandboxNotFound` for `egressLog`).

## Versions

| Package | Version | Licence | Role |
|---|---|---|---|
| `@grpc/grpc-js` | 1.14.6 | Apache-2.0 | runtime |
| `@grpc/proto-loader` | 0.8.1 | Apache-2.0 | runtime |
| `typescript` | 7.0.2 | Apache-2.0 | dev |
| `@types/node` | 20.19.43 | MIT | dev |

The transitive production dependencies are protobufjs, long, yargs and others. They are
all MIT, Apache-2.0, BSD-3-Clause or ISC, and `scripts/check-licences.mjs` checks them
against the SPEC licence rule. AES-256-GCM and SHA-256 come from `node:crypto`, so templates
add no dependency. Protos: `clovelly.cell.v1`, `clovelly.control.v1`, `clovelly.verifier.v1` and
`grpc.health.v1`, as copied into `proto/`.
