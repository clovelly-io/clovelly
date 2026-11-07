# clovelly-sdk (Python)

A thin, hand-written client for the confidential agent runtime: sandboxes under gVisor
inside Intel TDX cells. It speaks the gRPC protocol in `proto/clovelly/cell/v1/cell.proto`
and `proto/clovelly/control/v1/control.proto`, and trusts only the environment CA from the
customer's own verifier.

Python 3.9 or later. Import name `clovelly`.

## Install

```sh
cd sdks/python
uv venv --seed -p 3.12 .venv     # --seed puts pip in the venv; without it `pip` is the system's
. .venv/bin/activate
pip install -e .                 # or: uv pip install -e .
```

Tests use only the standard library (and the `openssl` CLI to make certificates):

```sh
python -m unittest discover -s tests -v
python check_licences.py         # every installed distribution against the licence rule
```

To regenerate the protobuf and gRPC modules after a change in `../../proto`:

```sh
pip install -e '.[dev]'          # grpcio-tools, pinned
./gen.sh
```

The generated `clovelly.cell.v1` and `clovelly.control.v1` packages are committed and land inside
the `clovelly` package (the proto packages are `clovelly.*`). Health checks use
`grpcio-health-checking`'s `grpc_health.v1`; generating `grpc.health.v1` would shadow the
`grpc` library.

## API

```python
import clovelly

env = clovelly.Environment(verifier_url, env_id, ca_bundle,
                       api_url=None, api_token=None, api_ca=None,
                       verifier_token=None, verifier_ca=None)
```

- `ca_bundle`: the environment CA, as PEM (str or bytes) or a path to a PEM file. It is
  the only trust anchor for cells.
- `env_id`: the environment id (a DNS label). It names the cells: `<subenv>.<env_id>.cells.clovelly.internal`.
- `verifier_url`: the customer's verifier, `https://host[:port]`. The SDK calls it to seal
  credentials and template keys and to read the receipt log, always with the SDK token
  `verifier_token` (default `CLOVELLY_VERIFIER_TOKEN`). `verifier_ca` (PEM or a path, default
  `CLOVELLY_VERIFIER_CA`) replaces the system roots for its certificate. The SDK never holds
  a DEK.
- `api_url`, `api_token`, `api_ca`: the control plane, a service setting rather than a
  trust input. `api_url` is `host:port` or `https://host:port`; `api_ca` is PEM or a path
  (unset: the system roots). Every control-plane call sends `authorization: Bearer <token>`.

```python
sb = env.sandbox(subenv, template=None, volume=None, volume_gib=None,
                 timeout=None, cpu=None, memory=None, command=None, env=None)
```

- `cpu` in vCPUs, a multiple of 0.5 (sent as halves); `memory` in GiB; `timeout` in
  seconds, at most 86400. None takes the sub-environment's default.
- `command`: the sandbox's optional main process, a shell string (run as
  `/bin/sh -c`) or an argv list. The sandbox ends when it exits. `env` is its environment.
- `template` and `volume`: see [Templates](#templates) and [Volumes](#volumes). `policy` is
  accepted for the SPEC's surface but must be None: a sub-environment has one policy bundle.
- Flow: `Control.PlaceSandbox` (blocks up to 330 s while a cell boots), connect to and
  verify the cell, a fresh 32-byte access key from `os.urandom`, `Cell.CreateSandbox`.
  A cell that refuses with `CAPACITY`, `CROSSES_CELL_END`, `CROSSES_RELEASE_EXPIRY`,
  `DRAINING` or `REVOKED` is added to `avoid_cells` and the sandbox placed again, up to
  three placements. Every abandoned placement is released.

`Sandbox` has `id`, `key` (hex; a secret, kept out of `repr`), `cell_id`, `cell_address`,
`subenv`, `cold`, `cpu`, `memory`, `timeout` (as placed, defaults filled in) and `timings`
in milliseconds: `place_ms`, `connect_ms` (0 when the connection was already verified),
`create_ms` (each summed over re-placements) and the cell's `runsc_ms`.

```python
r = sb.exec("python3 run.py", stdin=b"...", env={"K": "v"}, cwd="/work", timeout=60)
r.exit_code, r.stdout, r.stderr          # int, bytes, bytes
r.first_exec_ms                          # the cell's create-to-first-stdout, first exec only
r.first_stdout_at                        # time.perf_counter() at the first stdout chunk
r.sandbox_ended                          # e.g. "revoked" if the sandbox ended meanwhile

sb.files.write("/work/in.txt", b"data")  # bytes or str; returns bytes written
data = sb.files.read("/work/in.txt")     # bytes
receipt = sb.receipt()                   # interim while running
receipt = sb.close()                     # Kill, then Control.ReleaseSandbox (best effort)
receipt.doc, receipt.exit_kind, receipt.final        # dict, "killed", True

sb2 = env.reconnect(sb.id, sb.key)       # from any process: LocateSandbox, verify, GetReceipt
env.close()
```

`Sandbox` and `Environment` are context managers. One `Environment` is safe to share
between threads; it keeps one TLS connection per cell, and every sandbox on that cell
multiplexes its streams over it.

`env.cell(address, subenv)` returns the low-level `Cell` for tests that talk to a cell
directly: `.verify()` runs the probe, and `create_sandbox`, `exec`, `read_file`,
`write_file`, `kill` and `get_receipt` mirror the RPCs, passing ids and keys through
unchecked so the cell's own checks can be exercised.

## Regions

```python
pool = env.put_pool("bank-a", region="europe-west4", min_warm_per_zone=0, idle_window_secs=0)
pool.region, pool.zones                  # "europe-west4", ("europe-west4-a", ...)
```

A sub-environment's cells run in the region its pool names, one of the published list
(`docs/regions.md`); another name raises `UnknownRegion`, whose `.regions` is the list. The
region is set once: another region is another sub-environment. The control plane uses every
approved zone of it and hides a zone that is out of machines. When every zone of the region
is out and no cell can take the sandbox, `env.sandbox()` raises `NoCapacity` within seconds,
billing nothing, with `.region` and `.retry_after`. The SDK never queues it or tries another
region: that choice is yours, by creating the sandbox in a sub-environment elsewhere.

## Credentials

```python
env.put_credential("bank-a", "openai", api_key, adapter="bearer", destination="api.openai.com")
sb = env.sandbox("bank-a")
sb.exec("python3 call.py", env={"OPENAI_API_KEY": sb.cred("openai")})
```

`put_credential` sends the secret to the customer's own verifier (`verifier_url`, with the
SDK token), which seals it under the sub-environment's DEK, bound to the name, the adapter
type (`bearer`, `basic` or `query`, as the sub-environment's policy uses it) and the one
destination host; the control plane stores only that ciphertext. A sandbox never sees the
secret: `sb.cred(name)` (or `clovelly.placeholder(name)`) is the placeholder
`clovelly://cred/<name>`, which the cell's egress proxy replaces with the secret only in
requests to that destination. Elsewhere it is just a string.

A cell refuses a create with `PolicyRefused` while it holds no policy bundle it can accept,
and with `CredentialUnavailable` if a credential the policy names cannot be opened.

## Templates

```python
tpl = env.upload_template("bank-a", "analyst-v3", "analyst-v3.tar.gz")
tpl.name, tpl.digest, tpl.plaintext_bytes, tpl.ciphertext_bytes, tpl.parts
sb = env.sandbox("bank-a", template=tpl)          # or tpl.digest, or "analyst-v3"
tpl = env.template("bank-a", "analyst-v3")        # Control.GetTemplate
```

A template is a sandbox root given as a `.tar.gz`, stored per sub-environment under a name
(1-64 of a-z, 0-9, `_`, `-`, `.`; a later upload of the same name replaces it). Its digest
is the SHA-256 of the file, lowercase hex, and is what `CreateSandbox` and the sandbox's
receipt (`sandbox.template_digest`) name.

`upload_template` reads the file twice, 1 MiB at a time, and never holds it in memory:
once for the digest, then to encrypt and stream it. The customer's verifier
(`SealTemplateKey`, with the SDK token) issues a fresh 256-bit key for that digest together
with the same key sealed under the sub-environment DEK. The SDK encrypts with AES-256-GCM in
`crates/common/src/template.rs`'s chunked format, byte for byte (a test checks the Rust
encryptor's output hash), and streams `PutTemplate`: a header with the digest, sealed key and
size, then the ciphertext in messages just under 4 MiB. The control plane stores ciphertext
it cannot open; only a cell of the sub-environment can. A file that changes between the two
reads cancels the upload with `ValueError` before its last chunk is sent.

`env.sandbox(template=...)` takes a `Template`, a digest or a name. A name is resolved by the
control plane (`GetTemplate`, `NoSuchTemplate` if there is none) before placing; pass the
`Template` or its digest to pin the exact content. The cell checks the decrypted template
against the digest and refuses with `TemplateUnavailable` if it cannot fetch, open or match it.

## Volumes

```python
sb = env.sandbox("bank-a", volume="work", volume_gib=5)
```

`volume` names a persistent volume of the sub-environment (1-64 of a-z, 0-9, `_`, `-`),
mounted at `/volume`. It is created on first use with `volume_gib` GiB (1 to 20, default
1); `volume_gib` without `volume` is a `ValueError`. One sandbox mounts a volume at a time:
a second create is refused with `VolumeBusy`, and the SDK does not place it again. A volume
of another sub-environment or environment does not open (`VolumeUnreadable`); unreachable
blocks are `VolumeUnavailable`.

## Receipts

`sb.close()` and `sb.receipt()` (and the low-level `Cell.kill` and `Cell.get_receipt`) return
a `Receipt`:

| Field | Meaning |
|---|---|
| `json` | the receipt in JCS canonical form: exactly the signed bytes |
| `signature` | ECDSA P-256 with SHA-256 over `json` by the cell key, `r \|\| s` (64 bytes) |
| `cell_cert` | the signing cell's certificate (DER), which chains to the environment CA |
| `final` | the sandbox has ended; no later receipt will follow |
| `exit_kind` | `"running"` while it runs, then `"exited"`, `"killed"`, `"timeout"`, ... |
| `doc` | `json` parsed (`data` is the same dict, its name before phase 4) |

The SDK does not verify receipts. The public receipt tool does, from the receipt, the cell
certificate's chain to the environment CA and the published measurement set.

The cell also appends every receipt to the customer's log at their verifier, which keeps
the latest record per sandbox. Read it with the SDK token:

```python
for r in env.receipts("bank-a", sandbox_ids=[sb.id]):   # both optional: everything
    r.doc, r.final, r.received_unix_ms, r.records, r.finals, r.json, r.signature, r.cell_cert
log = env.egress_log(sb.id)            # GetEgressLog: log.lines, log.sha256
log.matches(r)                         # True: r's egress_log_hash is this log's hash
```

`egress_log` checks that SHA-256 over every line followed by a newline is the `sha256` the
verifier returned and raises `EgressLogMismatch` otherwise. `log.matches(receipt)` (a
`Receipt` or a `LoggedReceipt`) checks the receipt is for that sandbox and its
`egress_log_hash` is the log's hash; a receipt without one (no egress) matches only an
empty log. `clovelly.egress_log_sha256(lines)` computes the hash.

## Connection rules

Enforced by the SDK and not configurable off (SPEC.md "The SDK" and decision 2):

1. The cell is dialled at the address the control plane returned, as `ipv4:<host:port>`,
   with `grpc.ssl_target_name_override` and `grpc.default_authority` both set to
   `<subenv>.<env_id>.cells.clovelly.internal`. The sub-environment is the one the caller
   asked for, not one the control plane names.
2. The environment CA is the only root (`grpc.ssl_channel_credentials(root_certificates=ca)`).
   gRPC's standard verification checks the chain and the SAN; there are no custom
   certificate callbacks. The CA binds the environment, the SAN the sub-environment.
3. Before any call that carries data, the connection is probed with an empty
   `grpc.health.v1.Health/Check` (`wait_for_ready=False`, 15 s; a timeout, or a cell that
   cannot be reached yet, is retried for up to 90 s). gRPC sends nothing until the TLS
   handshake has verified the certificate, so a refused cell receives nothing beyond the
   handshake. A refusal raises `CellVerificationError` and the connection is dropped for
   good; a later request opens a fresh one, verified again.
4. Each `Cell` owns its connection (`grpc.use_local_subchannel_pool`), so closing a
   refused one really closes it and no connection is shared across environments.

## Errors

All errors derive from `clovelly.ClovellyError`, with `.reason` (the `clovelly-error` trailer, or
None), `.code` (the gRPC status code name) and `.details`.

| Reason (`clovelly-error`) | Type | From |
|---|---|---|
| `INVALID_SANDBOX_ID` | `InvalidSandboxId` | cell |
| `INVALID_REQUEST` | `InvalidRequest` | cell, control plane |
| `NO_SUCH_SANDBOX` | `SandboxNotFound` | cell, control plane |
| `PERMISSION` | `PermissionDenied` | cell, control plane |
| `SANDBOX_EXISTS` | `SandboxExists` | cell |
| `CAPACITY` | `CapacityError` | cell (re-placed) |
| `ABOVE_POLICY_MAXIMUM` | `AbovePolicyMaximum` | cell, control plane |
| `CROSSES_CELL_END` | `CrossesCellEnd` | cell (re-placed) |
| `CROSSES_RELEASE_EXPIRY` | `CrossesReleaseExpiry` | cell (re-placed) |
| `DRAINING` | `CellDraining` | cell (re-placed) |
| `REVOKED` | `CellRevoked` | cell (re-placed) |
| `SANDBOX_ENDED` | `SandboxEnded` | cell |
| `NO_SUCH_FILE` | `FileNotFound` | cell |
| `RUNTIME` | `RuntimeFailure` | cell |
| `POLICY_REFUSED` | `PolicyRefused` | cell |
| `CREDENTIAL_UNAVAILABLE` | `CredentialUnavailable` | cell |
| `TEMPLATE_UNAVAILABLE` | `TemplateUnavailable` | cell |
| `VOLUME_BUSY` | `VolumeBusy` | cell, control plane |
| `VOLUME_UNREADABLE` | `VolumeUnreadable` | cell |
| `VOLUME_UNAVAILABLE` | `VolumeUnavailable` | cell |
| `UNAUTHENTICATED` | `Unauthenticated` | control plane |
| `NO_SUCH_ENVIRONMENT` | `NoSuchEnvironment` | control plane |
| `NO_SUCH_SUBENVIRONMENT` | `NoSuchSubenvironment` | control plane |
| `NO_SUCH_POOL` | `NoSuchPool` | control plane |
| `NO_SUCH_CELL` | `NoSuchCell` | control plane |
| `NO_CELL_CAN_HOLD` | `NoCellCanHold` | control plane |
| `NO_CELL_READY` | `NoCellReady` | control plane |
| `CELL_CREATE_FAILED` | `CellCreateFailed` | control plane |
| `QUOTA_EXCEEDED` | `QuotaExceeded` | control plane |
| `NO_CAPACITY` | `NoCapacity` (`.region`, `.retry_after` seconds) | control plane |
| `UNKNOWN_REGION` | `UnknownRegion` (`.regions`, the published list) | control plane |
| `STORAGE` | `StorageUnavailable` | control plane |
| `NO_SUCH_TEMPLATE` | `NoSuchTemplate` | control plane |

A reason the SDK does not know raises a plain `ClovellyError` with `.reason` set. Without a
reason:

- `CellVerificationError`: the cell's TLS handshake failed. `.kind` is
  `"untrusted_certificate"` (self-signed or another CA), `"name_mismatch"` (the SAN
  names another environment or sub-environment) or `"handshake"` (anything else, such
  as a server without TLS); `.address` is the cell address.
- `CellUnavailable`: a cell whose certificate was not refused could not be reached or
  did not answer in time.
- `ControlPlaneUnavailable`: the control plane could not be reached or did not answer.
- `ProtocolError`: a server broke the protocol (a malformed placement, an Exec stream
  with no exit, a receipt that is not JSON). `EgressLogMismatch`, a subclass, is an egress
  log whose lines do not hash to the SHA-256 the verifier sent.
- `VerifierUnavailable`: the customer's verifier could not be reached or did not answer.
  It sends no reason trailer: UNAUTHENTICATED is `Unauthenticated`, INVALID_ARGUMENT
  `InvalidRequest`, NOT_FOUND `NoSuchSubenvironment` (`SandboxNotFound` for `egress_log`).

Bad arguments raise `ValueError` before anything is sent.

## Environment variables

| Variable | Used by | Meaning |
|---|---|---|
| `CLOVELLY_API_URL` | `Environment` | control plane `host:port` or `https://host:port` |
| `CLOVELLY_API_TOKEN` | `Environment` | the environment's API token |
| `CLOVELLY_API_CA` | `Environment` | the control plane's CA (PEM or path); unset uses system roots |
| `CLOVELLY_VERIFIER_TOKEN` | `Environment` | the verifier's SDK token: `put_credential`, `upload_template`, `receipts`, `egress_log` |
| `CLOVELLY_VERIFIER_CA` | `Environment` | the verifier's CA (PEM or path); unset uses system roots |
| `CLOVELLY_VERIFIER_URL`, `CLOVELLY_ENV_ID`, `CLOVELLY_CA_BUNDLE`, `CLOVELLY_SUBENV` | `examples/smoke.py` | the `Environment` arguments and the sub-environment |

`examples/smoke.py` runs phase 2 criterion 1 (create, `exec("python3 -c 'print(6*7)'")`,
write and read a file, close) and prints one JSON object with each step's result and
timing; it exits non-zero on any failure.

## Versions

| Distribution | Version | Licence | Role |
|---|---|---|---|
| `grpcio` | 1.74.0 | Apache-2.0 | runtime |
| `grpcio-health-checking` | 1.74.0 | Apache-2.0 | runtime |
| `protobuf` | 6.33.6 | BSD-3-Clause | runtime |
| `cryptography` | 45.0.7 | Apache-2.0 OR BSD-3-Clause | runtime (AES-256-GCM for templates) |
| `cffi` | 2.0.0 | MIT | runtime (cryptography's, not on PyPy) |
| `pycparser` | 2.23 | BSD-3-Clause | runtime (cffi's, not on PyPy) |
| `grpcio-tools` | 1.74.0 | Apache-2.0 | dev (`gen.sh`) |

Pinned exactly. `grpcio` 1.74.0 is the newest release that satisfies the licence rule:
from 1.75.0 on, `grpcio` depends on `typing-extensions`, which is PSF-2.0 and not on the
allowlist (`check_licences.py` fails on it). Its wheels cover CPython 3.9 to 3.13. Newer
pins need either an exemption for `typing-extensions` or a grpcio release without it.
`protobuf` 6.33.6 is the last release supporting Python 3.9 and is within
`grpcio-health-checking`'s `protobuf>=6.31.1,<7`. Code generated by `grpcio-tools`
1.74.0 runs on any `grpcio` 1.74.0 or later.

`cryptography` 45.0.7 is pinned for the same reason as `grpcio`: from 46.0.0 it depends on
`typing-extensions` on Python before 3.11. Its wheels bundle OpenSSL 3.5.2; the SDK uses
only AES-256-GCM from it. It states its licence in the `License` field rather than
`License-Expression`, which `check_licences.py` maps. `cffi` 2.0.0 and `pycparser` 2.23
are the newest releases that install on Python 3.9 (`cffi` 2.1 and `pycparser` 3 need 3.10).
