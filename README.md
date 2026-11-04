# Clovelly

Clovelly, by Altquid, Inc., runs general-purpose code sandboxes where the provider
cannot see inside and the customer can prove it: for AI agents, CI, data jobs or
anything else you would rather not run on a machine someone else can read. Sandboxes
run under gVisor inside Intel TDX
confidential VMs ("cells") on Google Cloud. Each customer runs a verifier in their own
project that checks every cell's attestation before releasing keys from the customer's
KMS, and the SDKs refuse to talk to a cell the verifier has not vouched for.

This repository is the trusted base: everything whose hash appears in a cell's quote,
and everything a customer runs. A measurement is a hash; this source is what lets you
tie that hash to code you can read.

| Path | What it is |
|---|---|
| `image/`, `flake.nix` | The cell image: Nix recipe, kernel, init, Secure Boot certificates |
| `crates/cell-agent`, `crates/egress-proxy` | The in-cell agent and egress proxy |
| `crates/common`, `crates/measure` | Shared types and protocol bindings; the RTMR predictor |
| `crates/verifier`, `deploy/verifier.sh` | The verifier you deploy ([guide](docs/verifier-deploy.md)) |
| `crates/rebuild`, `release/` | Rebuilding a release and comparing it with the public log ([REPRODUCE.md](REPRODUCE.md)) |
| `crates/receipt-tool` | `clovelly-receipt`: checks a sandbox receipt |
| `sdks/`, `proto/` | The Python (`clovelly`) and TypeScript (`@clovelly/sdk`) SDKs and the gRPC protocol |
| `docs/quickstart.md` | From nothing to your first sandbox |
| `docs/evidence-pack.md` | Everything you need to check our claims, in one index |
| `docs/threat-model.md` | What the system trusts and defends against |

## Building and testing

```bash
cargo test --workspace
```

```bash
release/rebuild.sh
```

`release/rebuild.sh` builds the unsigned release images and their build record; see
[REPRODUCE.md](REPRODUCE.md) for comparing them with a release.

## Licences

The trusted base is under the Functional Source License, version 1.1, with Apache 2.0
as the future licence (`FSL-1.1-ALv2`, [LICENSE](LICENSE)): you may read, rebuild,
audit and run it for your own use, but not sell it as a competing service; each version
becomes Apache-2.0 two years after its release. The SDKs and protocol files are
Apache-2.0 ([sdks/LICENSE](sdks/LICENSE), [proto/LICENSE](proto/LICENSE)).

Comments in the code cite `SPEC.md`, `DECISIONS.md` and `BLOCKERS.md`: our internal
engineering spec and decision logs, which are not published.
