# How the cell images are made reproducible

Two builds of the same commit with the same signing key must produce byte-identical
`disk.raw` files and the same predicted RTMR1 and RTMR2 (SPEC.md phase 1 criteria 6
and 7). These are the sources of variation and how each is fixed.

| Source | Where | Fix |
|---|---|---|
| Inputs | everything | nixpkgs pinned by commit in `flake.lock`; runsc pinned by SHA-512; Go tools by commit and vendor hash; Rust crates by `Cargo.lock` (vendored by `buildRustPackage`). |
| Compiler and flags | `cell-agent`, `measure`, `verifier` | One rustc from the pinned nixpkgs; `rust-toolchain.toml` names the same version for local builds. Nix sets `SOURCE_DATE_EPOCH` and remaps store paths. |
| File times | erofs root | `mkfs.erofs -T0 --ignore-mtime`: every inode has time 0. |
| File owners | erofs root | `--all-root`. |
| Filesystem UUID | erofs root | `-U c4a7c0de-…-000000000001`. |
| dm-verity salt and UUID | hash tree | `--salt=63617274 00…` (fixed), `--uuid=c4a7c0de-…-000000000002`. |
| Disk and partition GUIDs | GPT | `label-id` and each partition's `uuid` fixed in the `sfdisk` script. |
| FAT volume id and times | ESP | `mkfs.vfat -i 43415254`; `SOURCE_DATE_EPOCH=0` and `mcopy -m` for the UKI's timestamps. |
| UKI | ESP | `ukify` with the kernel, initrd and command line from the store; systemd-stub from the pinned systemd. The command line is written with `printf '%s'` (no trailing newline). |
| Initrd | UKI | `makeInitrdNG` with zstd: sorted entries, fixed times. |
| Secure Boot signature | UKI | `sbsign` signs with RSA PKCS#1 v1.5, which is deterministic for a given key and image, but its PKCS#7 carries a signing time from the clock (found when two builders' UKIs differed only there). It runs under `faketime -f` with the clock frozen at 1980-01-01; without `-f`, faketime only starts the clock there, and two builders' `test` UKIs then differed by one second of signing time. Firmware ignores the signing time. The signature does not enter the measurements: Authenticode excludes the certificate table, so RTMR1 is the same for a signed and an unsigned UKI. |
| Tarball | `disk.raw.tar.gz` | `tar --mtime=@0 --owner=0 --group=0 --numeric-owner --format=oldgnu -S`, `gzip -n`. |
| Release id | `/clovelly/release` | `clovelly-<version>-<variant>`, from `image/default.nix`, not from the clock or the commit. |

## The signing key is an input

Images are built with `--impure` so the flake can read `CLOVELLY_SIGNING_KEYS`, the
directory with the db key (`release/nix.sh` mounts it). Nix copies the
directory into the store by content, so the key is an ordinary, content-addressed
input: the same key gives the same image. Someone without our key cannot reproduce the
signed bytes of `uki.efi` or `disk.raw`, but can rebuild everything else and compare
the measurements, which do not depend on the signature. The release pipeline (phase 5)
therefore compares the unsigned images, `image-prod-unsigned` and `image-test-unsigned`,
which need no key: the two builders, and any rebuilder following `REPRODUCE.md`, build the
same bytes, and their predicted RTMR1 and RTMR2 are the signed images'. Signing stays
with the operator's db key; moving it into KMS or an HSM is still to do.

## Checking

Since phase 5, `release/rebuild.sh` builds both unsigned images and writes their record,
and `clovelly-rebuild compare A B` is the gate.
Before it: `release/nix.sh build-to image-test build/a` and the same into `build/b` from a
second, empty Nix store (`CLOVELLY_NIX_VOLUME=clovelly-nix-b`): `cmp build/a/disk.raw.tar.gz
build/b/disk.raw.tar.gz` and the two `predicted-rtmr` files must match, for `image-prod`
and `image-test`.
