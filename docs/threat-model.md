# Verifier threat model

The verifier decides whether a machine may hold a customer's keys. This document says
what it trusts, what it defends against, how, and what it leaves open as of phase 1.
Deployment is in [verifier-deploy.md](verifier-deploy.md); the design is in
`SPEC.md`, "The verifier".

## Parties and trust

| Party | Role | Trusted for |
|---|---|---|
| Customer | Runs the verifier, the key helper and the key manager; owns DEKs and the environment CA. | Everything they run. |
| Us (the provider) | Build the cell images, run the hosts' control plane, GCS, the network and instance metadata. | Nothing at unlock time. Our release key signs which images exist; anyone can rebuild them and compare measurements (phase 5 adds the public log). |
| Intel | TDX module, quoting enclave, PCK certificates, collateral (PCS). | That a quote comes from a genuine, patched TDX platform. |
| Google | Firmware (TDVF), MR_OWNER binding, host registry, firmware endorsements. | The firmware it endorses and the project, zone and instance it writes into MR_OWNER. |

We are the adversary the verifier is built against. We control the host, the
hypervisor and everything outside the TD: the disk the cell boots from, its UEFI
variables and boot entries, instance metadata, DNS and the network path to the
verifier. Physical attacks on the CPU (TEE.fail, DDRop) are out of scope.

## Assets

- **Sub-environment DEKs.** Decrypted by the customer's key manager for each unlock, through
  the key helper, HPKE-sealed to one cell's key, never stored by the verifier.
- **The environment CA key.** In the key manager; signs one certificate per unlocked cell.
- **The policy key.** In the key manager; signs each sub-environment's policy bundle. Its public key
  goes to each cell at every unlock and renewal, and the cell verifies every bundle against
  the keys its latest lease named, one normally and two while the key rotates
  ([key-rotation.md](key-rotation.md)). The same verifier names them that issued the cell's
  certificate, so a key change trusts nothing the first unlock did not.
- **Credentials.** The customer's SDK sends a credential's secret to the verifier
  (`SealCredential`), which seals it under a key derived from the sub-environment DEK,
  bound to its name, adapter type and destination, and returns only ciphertext. The
  secret is in the verifier's memory for that call.
- **The SDK token.** Authorises `SealCredential`; the configuration holds its SHA-256.
- **The cell's private key.** Generated in the TD at boot; never leaves it.

## What a cell must prove, and how

A cell sends a quote, its CC event log (CCEL), and claims: environment, sub-environment,
release, its public key, the nonce, and its GCE instance id, zone and name. All ten checks run
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
| Spoof or hide a cell's network address | Nothing relies on it. A cell's identity is its quote (check 7), never where its packets came from. Cells reach a verifier on Google Cloud over Google's private path, so it sees no source IP of theirs, and a verifier anywhere else from the addresses in [static-egress-ips.md](static-egress-ips.md), which a customer may allowlist as one more filter and no more. |
| Point a cell at a fake verifier | The cell talks TLS to the URL it was given. A fake verifier has no DEK to give, and its certificate does not chain to the customer's CA, so SDKs refuse the cell (phase 2). A wrong URL means no unlock; the agent gives up after 5 minutes and the cell is recycled. |
| Serve a cell a different policy bundle | Bundles are signed by the customer's policy key and name their environment and sub-environment; the cell refuses a bundle that does not verify, is for another scope, has expired or is older than the one in force, and then creates no sandbox until it gets one it accepts. `GetPolicy` is open: a bundle is not secret. |
| Plant or swap a credential | `SealCredential` needs the SDK token. The ciphertext's associated data names the environment, sub-environment, credential, adapter type and destination, so whoever stores it (the control plane) cannot move it to another name or host, and a cell releases it only for the destination and adapter its policy uses there. |
| Lie in metadata (environment, sub-environment, instance id, zone) | Each claim is bound by a check: env by REPORTDATA, instance and zone by MR_OWNER. The sub-environment only selects which DEK is sealed to the cell; a cell of the right environment asking for another sub-environment's DEK gets a certificate that names that sub-environment. |
| Lie about the instance name | Nothing binds it to the quote, and nothing needs to. It only names the cell in its certificate's second SAN, `<instance>.<zone>.<subenv>.<env>.cells.clovelly.internal`; the zone in that name passed check 7, and a name that is not one DNS label is refused before any check runs. An unattested machine gets no certificate at all, and an attested cell of the sub-environment that claimed another cell's name already holds a certificate from the same CA and the same DEKs as that cell, so the name gains it nothing it did not have. |

## Who may create a sandbox

A cell creates a sandbox only with a placement pass (`placement_pass`, from `PlaceSandbox`): the control plane's
signature, with a key and certificate it holds for nothing else, over the cell's name, the sandbox id, its size and
its timeout, good for 10 minutes and taken once. Every deployment of the control plane holds a pass key of its own,
issued at each deploy and good for 30 days, under the one control-plane CA, and its certificate names the
deployment's GCP project number. The cell checks the pass under the control-plane CA baked into its measured image,
and that its certificate names the cell's own project, before it touches a template, a volume or a credential, and
refuses anything else (`PLACEMENT_REFUSED`). So nobody who merely reaches a cell can create a sandbox in your
sub-environment, and a pass key from another deployment places nothing on this one's cells.

| Attack | Stopped by, or not |
|---|---|
| Create a sandbox on a cell without asking the control plane, or reuse an old placement | Stopped: the pass names this cell and this sandbox, expires, and is taken once. |
| Sign a pass with another of our certificates (the `Drain` or cell-channel one) | Stopped: the cell requires the pass-signing key usage. |
| Sign a pass with a key leaked from another deployment (a staging or test deployment's) | Stopped: the certificate names its deployment's project, and the cell accepts only its own. The cell's project is the attested one: it takes the metadata server's project number only when the MR_OWNER it predicts (GCE's SHA-384 over the project, zone and instance, the same function the verifier uses) equals the MR_OWNER of the quote the verifier accepted at unlock, which the verifier checked against its own policy's project. A host that names another project in metadata gets a cell that refuses every create. A key of the same deployment, from any deploy in the last 30 days, still signs; none can be revoked before it expires. |
| **We, through the control plane, create a sandbox in your sub-environment** | **Not stopped.** The control plane decides who places, so we, as its operators, could create a sandbox there, and that sandbox would get what the sub-environment's policy releases to any sandbox: its sealed credentials through the egress proxy, its volumes by name and its templates. It would not get your DEK or a key we could take away, and its cell's receipt log records it. A second signature on the pass, from a key you hold, would close this; it is not built. |
| Replay a pass after the cell agent restarts, or on a cell whose clock is behind | The cell remembers passes in memory, for their 10 minutes: an agent that restarts within them could take one again if its sandbox is gone. A cell checks expiry by its own clock, which chrony keeps on Google's time; one whose first sync failed and runs behind accepts passes past their expiry. Both need a pass the control plane issued for that cell. |
| Boot a cell without the control-plane metadata | Such a cell checks no pass (it has no control plane to place on it). Only we set an instance's metadata, at its creation through Compute, so this is ours to misuse, not anyone else's; the cell still unlocks only by attestation. |

## The relay in front of the cells

Cells have no address of their own on the internet. Each region has one static address (listed in
[regions.md](regions.md)) in front of a relay we operate: two small VMs running HAProxy in TCP mode. The SDK dials
that address with the cell's own name as the TLS server name; the relay reads the name from the TLS ClientHello,
takes its first two labels (instance and zone), looks the instance up in Google's internal DNS and copies bytes
between the client and that cell's port 443. It terminates no TLS and holds no key or credential (its VMs run with
no service account), so the TLS session is between the SDK and the cell, and the SDK checks the cell's certificate
against the environment CA exactly as it would without the relay.

| Attack (by us, through the relay) | Stopped by |
|---|---|
| Read or change a sandbox's traffic | TLS end to end between the SDK and the cell. The relay sees ciphertext. |
| Send a connection to another cell, or to a machine of ours | The certificate must chain to the customer's environment CA and carry the cell name the SDK dialled, which the SDK checked is under the expected sub-environment. Another cell's certificate names another cell, and no machine of ours has a certificate from the customer's CA. The SDK refuses the handshake (`name_mismatch`, `untrusted_certificate`) and sends nothing. The network also lets the relay's VMs reach only cells, and only on port 443. |
| Refuse or cut connections | The SDK sees a transport error and retries; this is denial of service, which we can always do. |

What the relay learns: which cell each connection is for (the name in the handshake, which the control plane that
placed the sandbox already knows), when, and how many bytes went each way. It logs those and the outcome, and nothing
else: no client address and no content. The customer's network sees the region's relay address, not the cell's.

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
- **The customer's platform and key manager.** The verifier runs on infrastructure the customer
  chose. That platform's operator, or anyone with the customer's rights on it, can read its
  memory or call the key manager directly. The verifier is the customer's component, not ours.

## The key helper

The verifier holds no key-manager code. It reaches the customer's keys through one small HTTP
interface on its own loopback ([key-helper.md](key-helper.md)), served by a second container: ours for
Cloud KMS and AWS KMS, or one the customer wrote. What that means:

- **The helper is inside the customer's trust.** It can sign as the environment CA and see every
  DEK. Whoever can reach it can too, so the interface has no authentication and must not be on a
  network: the verifier refuses to start on an address that is not loopback, written as a number, and the
  reference helpers refuse to bind one. On a platform where something else shares that loopback (another
  container in the same pod or task, a debugging sidecar), that thing can use the keys: **it is the customer's
  to keep the verifier's neighbours out.** A key manager's audit log shows the helper's identity on every use.
- **A helper is not trusted about signatures.** The verifier checks each one under the key it should be
  from before it uses it, and for a cell certificate that key is the one in the customer's own CA certificate,
  whatever the helper says its key is. A helper that answers in the wrong format or with another key is refused,
  and nothing is issued.
- **A helper can return a wrong DEK.** Nothing can catch that at unlock: the configuration holds only
  ciphertext. A wrong DEK fails where it is used, on a credential or volume that does not open, and
  `verifier check-keys` is the test of a helper's decrypt. It is the customer's own helper giving the customer's
  own cell a key, so this is a fault to find and not a boundary to defend.
- **A helper that is down, slow or refusing fails closed.** Every request has 10 seconds. A failure gives the cell
  `UNAVAILABLE`, no certificate and no key, and is logged. Running cells keep their lease until it ends, at most 60
  minutes, then end their sandboxes.
- **The reference helpers' identity is least privilege.** `clovelly-keys init` grants the role it will run as what
  it needs on each of the three keys and nothing else: sign and read public keys on two, decrypt on the third. It
  cannot create, delete, disable or re-key, and `clovelly-keys check-role` proves that against the real key manager.
- **We ship no helper that holds a private key itself,** in a file, an environment variable or memory. A customer who
  writes one has chosen a weaker verifier than ours: nothing then stops the key being copied, there is no key
  manager's audit log, and revoking it means trusting whoever holds the copy.
- **The images are the same for everyone.** The verifier's image is byte-identical for every customer, so a customer
  can compare its digest with the one in the signed release, or rebuild it (`REPRODUCE.md`). The helper is a separate
  container for that reason.

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
  buffers that carry the key helper's response are freed without wiping.
- **The cell's TLS key.** The cell agent wipes its own copies of the private key; tonic,
  which serves TLS, keeps one in its configuration for the cell's lifetime. The cell
  key also serves as the HPKE recipient and receipt key, as the spec requires.
- **RTMR0 depends on the VM's shape.** Machine type (ACPI tables, TD HOB) and PCI layout
  (the boot entry's device path) are measured. Every cell of a release must use a shape
  and VM options an RTMR0 was recorded on (Secure Boot, no vTPM, no display device). A
  release lists one RTMR0 per host firmware and shape, each named with its
  `machine_type` (c3-standard-8, and c3-standard-88 from the release after 0.5.0); a
  verifier accepts a quote whose RTMR0 is any listed value, so a shape's value is
  trusted exactly as another shape's.
- **MRSEAM is an allow list.** When Google moves hosts to a new TDX module, check 4
  refuses cells on it until the policy lists the new MRSEAM.
- **The staging verifier also trusts test releases.** Their policy is signed by a
  staging-only key that no customer verifier trusts; test images carry a results channel
  and must never unlock a real environment.
- **The SDK token is a bearer secret.** Whoever holds it can have credentials sealed for
  the environment (they cannot read existing ones). Keep it with the API token.
- **Not yet built.** The firmware endorsement mirror (phase 5; endorsements are fetched
  from Google's bucket) and Rekor inclusion proofs (phase 5).
