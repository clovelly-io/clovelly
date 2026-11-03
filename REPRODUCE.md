# Rebuilding a release

This is how anyone, with no access to our infrastructure, checks that a released cell
image is the one built from this source: rebuild it, and compare what you get with
what we logged in Sigstore's public Rekor log when we released it. It needs nothing of
ours but this repository and our public release key, which is in it
(`release/release-key.pub`).

## What you need

- A machine with Docker (any OS; the build runs the pinned `nixos/nix` container as
  x86_64), or Linux x86_64 with Nix 2.18 or later with flakes. About 60 GB of free disk
  and an internet connection (sources and cached packages come from GitHub, cache.nixos.org
  and upstream mirrors, each pinned by hash).
- git, and Rust (rustup reads `rust-toolchain.toml`) for the comparison tool, or jq if
  you would rather compare by hand.

The build takes about 10 minutes on 44 cores and one to two hours on 4.

## Steps

1. Clone the repository at the release's tag. The tag is `v` and the release's version:
   release `clovelly-0.3.0` is tag `v0.3.0`.

   ```bash
   git clone https://github.com/clovelly-io/clovelly
   ```

   ```bash
   cd clovelly && git checkout v0.3.0
   ```

2. Rebuild, with one command:

   ```bash
   release/rebuild.sh
   ```

   It builds the unsigned `prod` and `test` images (`nix build .#image-prod-unsigned`
   and `.#image-test-unsigned`, through `release/nix.sh`) and writes their record to
   `build/rebuild/build.txt`: the commit, each image's Nix derivation (the recipe), the
   SHA-256 of its `disk.raw`, and its predicted RTMR1 and RTMR2. No signing key is
   involved.

3. Get the release's fragment: `fragment.json` among the release's assets on GitHub
   (<https://github.com/clovelly-io/clovelly/releases/tag/v0.3.0>; it is also in the
   fragments index verifiers fetch). It holds the exact payload we logged, our
   signature, and the Rekor entry with its inclusion proof.

   ```bash
   curl -sLO https://github.com/clovelly-io/clovelly/releases/download/v0.3.0/fragment.json
   ```

4. Check the fragment and compare:

   ```bash
   cargo run -q --release -p rebuild -- match --build build/rebuild/build.txt --bundle fragment.json --release-key release/release-key.pub --rekor-key crates/verifier/roots/rekor.sigstore.dev.pub
   ```

   This verifies, as a customer's verifier does, our signature on the fragment, the
   payload against the closed schema, the Rekor entry's inclusion proof to a checkpoint
   the log signed, the log's signed entry timestamp, and that the entry is a DSSE
   envelope over exactly this payload signed by our key. Then it compares the payload's
   release id, commit, recipe, disk hash, RTMR1 and RTMR2 with your rebuild, one line
   each, and exits non-zero on any difference.

5. Do not take our copy of Rekor's key on trust: compare it with the log's own.

   ```bash
   curl -s https://rekor.sigstore.dev/api/v1/log/publicKey | diff - crates/verifier/roots/rekor.sigstore.dev.pub
   ```

   You can also read the entry from the log directly (the index is in the release notes)
   and check that its `payloadHash` is the SHA-256 of the payload in `fragment.json`.

## What a match means

Every cell quotes RTMR1 and RTMR2, and the customer's verifier unlocks a cell only if
they equal a published release's (check 6, with a CCEL replay). RTMR1 covers the
unified kernel image's Authenticode hash, which covers the kernel, the initrd and the
command line, and the command line names the dm-verity root hash, which covers the
whole read-only root. RTMR2 covers each section the stub loaded, the command line
among them. So a rebuild whose RTMR1 and RTMR2 match the logged ones is the software
every unlocked cell of that release runs.

What a rebuild cannot give you:

- The Secure Boot signature. The images we boot are signed with our Secure Boot db key;
  you build them unsigned. The signature is the only difference (in the image's EFI
  partition), and Authenticode leaves it out of RTMR1, so the measurements are the same.
  Our db, KEK and PK certificates are public in `image/secureboot/`.
- RTMR0 and MRTD. They measure Google's firmware and our Secure Boot keys, not the
  image. MRTD is checked against Google's signed endorsement for that firmware; RTMR0 is
  recorded from a canary cell on each firmware, reviewed by a person against the event
  log, and published in the release's payload (`measurements.firmware`).
- RTMR3 is zero: nothing extends it.

How the images are made reproducible is in `image/DETERMINISM.md`.
