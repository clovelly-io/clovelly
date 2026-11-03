# Verifier threat model

The verifier decides whether a machine may hold a customer's keys. This document says
what it trusts, what it defends against, how, and what it leaves open as of phase 1.
Deployment is in [verifier-deploy.md](verifier-deploy.md); the design is in
`SPEC.md`, "The verifier".

## Parties and trust

| Party | Role | Trusted for |
|---|---|---|
| Customer | Runs the verifier and KMS; owns DEKs and the environment CA. | Everything they run. |
| Us (the provider) | Build the cell images, run the hosts' control plane, GCS, the network and instance metadata. | Nothing at unlock time. Our release key signs which images exist; anyone can rebuild them and compare measurements (phase 5 adds the public log). |
| Intel | TDX module, quoting enclave, PCK certificates, collateral (PCS). | That a quote comes from a genuine, patched TDX platform. |
| Google | Firmware (TDVF), MR_OWNER binding, host registry, firmware endorsements. | The firmware it endorses and the project, zone and instance it writes into MR_OWNER. |

We are the adversary the verifier is built against. We control the host, the
hypervisor and everything outside the TD: the disk the cell boots from, its UEFI
variables and boot entries, instance metadata, DNS and the network path to the
verifier. Physical attacks on the CPU (TEE.fail, DDRop) are out of scope.

## Assets

- **Sub-environment DEKs.** Decrypted from KMS for each unlock, HPKE-sealed to one
  cell's key, never stored by the verifier.
- **The environment CA key.** In KMS; signs one certificate per unlocked cell.
- **The policy key.** In KMS; signs each sub-environment's policy bundle. Its public key
  goes to each cell at unlock, and the cell verifies every bundle against the key from
  its first unlock.
- **Credentials.** The customer's SDK sends a credential's secret to the verifier
  (`SealCredential`), which seals it under a key derived from the sub-environment DEK,
  bound to its name, adapter type and destination, and returns only ciphertext. The
  secret is in the verifier's memory for that call.
- **The SDK token.** Authorises `SealCredential`; the configuration holds its SHA-256.
- **The cell's private key.** Generated in the TD at boot; never leaves it.

## What a cell must prove, and how

A cell sends a quote, its CC event log (CCEL), and claims: environment, sub-environment,
release, its public key, the nonce, and its GCE instance id and zone. All ten checks run
on every request and every outcome is logged; the cell is told only the number of the
first check that failed.

| Attack (by us, or anyone on the path) | Stopped by |
|---|---|
| Forge a quote, or replay one from another machine | Check 1: quote, QE report and PCK chain signatures to Intel's root; TCB info and QE identity signed by Intel. |
| Use a revoked or unpatched platform | Check 2: PCK and root CRLs fetched within the hour, current, signed by their issuers, not revoking the chain. Check 3: TCB status `UpToDate` (or `SWHardeningNeeded` with allow-listed advisories), QE identity and TDX module identity match. |
| Boot a TD in debug mode, or with different CPU features or TDX module | Check 4: DEBUG off; XFAM exact; MRSEAM on the allow list; TEE_TCB_SVN at or above the floor. |
| Boot other firmware | Check 5: MRTD is in Google's signed endorsement for the firmware (RSA-PSS chain to the pinned GCE-cc-tcb-root_1). |
| Boot another image, kernel, command line or root, or another Secure Boot state | Check 6: the CCEL replays to the quote's RTMRs, and RTMR0..3 equal the release's published values. Never relaxed. |
| Run the image somewhere other than our project and allowed zones | Check 7: MR_OWNER is SHA-384 of the claimed instance, our project number and an allowed zone; the PPID is in Google's host registry. |
| Replay an old unlock, or use one cell's quote for another key or environment | Check 8: REPORTDATA = SHA-512("clovelly-v1" ‖ env ‖ SHA-256(SPKI) ‖ nonce); the nonce was issued by this verifier for this environment, is under 5 minutes old and is used once. |
| Push an untested release, or an old release after a CVE | Check 9: the release is in the signed policy and past its notice window, or pinned by the customer. Check 10: before `valid_until`, pinned or not. |
| Intercept the DEK | HPKE to the key bound by check 8; the `info` names the environment and sub-environment. Only that cell's private key opens it (criterion 5's test). |
| Spoof or hide a cell's network address | Nothing relies on it. Cells reach Cloud Run over Google's private path, so the verifier sees no source IP of theirs (Cloud Run logs `0.0.0.0`); a cell's identity is its quote (check 7), never where its packets came from. |
| Point a cell at a fake verifier | The cell talks TLS to the URL it was given. A fake verifier has no DEK to give, and its certificate does not chain to the customer's CA, so SDKs refuse the cell (phase 2). A wrong URL means no unlock; the agent gives up after 5 minutes and the cell is recycled. |
| Serve a cell a different policy bundle | Bundles are signed by the customer's policy key and name their environment and sub-environment; the cell refuses a bundle that does not verify, is for another scope, has expired or is older than the one in force, and then creates no sandbox until it gets one it accepts. `GetPolicy` is open: a bundle is not secret. |
| Plant or swap a credential | `SealCredential` needs the SDK token. The ciphertext's associated data names the environment, sub-environment, credential, adapter type and destination, so whoever stores it (the control plane) cannot move it to another name or host, and a cell releases it only for the destination and adapter its policy uses there. |
| Lie in metadata (environment, sub-environment, instance id, zone) | Each claim is bound by a check: env by REPORTDATA, instance and zone by MR_OWNER. The sub-environment only selects which DEK is sealed to the cell; a cell of the right environment asking for another sub-environment's DEK gets a certificate that names that sub-environment. |

### The kernel command line

Phase 0 found that systemd-stub accepts command-line load options when Secure Boot is
off. Phase 1 closes this twice:

1. **Secure Boot with our own keys.** GCE images carry our PK, KEK and db (no Microsoft
   certificates). The UKI is signed with the db key, so firmware will not start an
   unsigned UKI or one signed by another key: such a cell never leaves firmware. With
   Secure Boot on, systemd-stub ignores load options. The SecureBoot variable, our keys
   and the db certificate that authorised the UKI are measured into RTMR0.
2. **The RTMR pin (check 6).** The command line is the UKI's `.cmdline` section, measured
   into RTMR2. The UKI file is measured into RTMR1 as well, so a different command line
   moves RTMR1 and RTMR2. Without Secure Boot, load options would move RTMR2 (the stub
   measures them) and RTMR0 (the boot entry that carries them). Either way check 6
   refuses the cell.

The cell agent also refuses to start unless the command line it booted with is the
measured one, its `clovelly.roothash=` is the root dm-verity mounted, and Secure Boot was on
(boot step 1). This is defence in depth, because a malicious image would not run our
agent; the verifier's check 6 is the control that matters.

## What the verifier trusts that it cannot check

- **Intel and Google.** A compromised Intel signing key or Google endorsement key
  defeats checks 1 to 5 and 7. The roots are pinned in the verifier; rotating one is a
  verifier release, never a silent fetch.
- **Our release policy.** The verifier accepts what our release key signs. Phase 5 adds
  public logging (Rekor) and the notice window, so a customer can see a release before
  their verifier accepts it and rebuild it to check its measurements.
- **Cloud Run and KMS.** The verifier runs on Google's infrastructure in the customer's
  project. Google, or anyone with the customer's project IAM, can read its memory or
  call KMS directly. The verifier is the customer's component, not ours.

## Known limits in phase 1

- **Unlock is once per cell.** The certificate and DEKs last 60 minutes, the cell's whole
  phase 1 lifetime. Phase 2 makes that a lease: the cell repeats the unlock with a fresh
  nonce from 45 minutes, the verifier re-runs all ten checks, and a cell that cannot renew
  zeroises its DEKs and ends its sandboxes. A cell may then live up to 48 hours while a
  revoked key, a removed release or an expired one still takes effect within the hour.
- **Nonces are per instance.** The nonce store is in memory, so the service runs with at
  most one instance. A restart forgets issued nonces (cells retry) and used nonces
  (they have also expired by then). Scaling out needs a shared store.
- **No rate limiting.** `GetNonce` and `Unlock` are public; nonces are pruned after twice
  their TTL, but a flood can exhaust the one instance. Cloud Armor or quotas belong in
  front of it in production.
- **Plaintext DEKs in verifier memory.** Our own copies are wiped; the HTTP and JSON
  buffers that carry KMS's response are freed without wiping.
- **The cell's TLS key.** The cell agent wipes its own copies of the private key; tonic,
  which serves TLS, keeps one in its configuration for the cell's lifetime. The cell
  key also serves as the HPKE recipient and receipt key, as the spec requires.
- **RTMR0 depends on the VM's shape.** Machine type (ACPI tables, TD HOB) and PCI layout
  (the boot entry's device path) are measured. Every cell of a release must use the
  shape and VM options its RTMR0 was recorded on (c3-standard-8, Secure Boot, no vTPM,
  no display device).
- **MRSEAM is an allow list.** When Google moves hosts to a new TDX module, check 4
  refuses cells on it until the policy lists the new MRSEAM.
- **The staging verifier also trusts test releases.** Their policy is signed by a
  staging-only key that no customer verifier trusts; test images carry a results channel
  and must never unlock a real environment.
- **The SDK token is a bearer secret.** Whoever holds it can have credentials sealed for
  the environment (they cannot read existing ones). Keep it with the API token.
- **Not yet built.** The firmware endorsement mirror (phase 5; endorsements are fetched
  from Google's bucket) and Rekor inclusion proofs (phase 5).
