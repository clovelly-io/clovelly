# Rotating keys

Every key here is yours and lives in your Cloud KMS, except the control-plane mTLS CA,
which is ours and rotates as a release. Each procedure below keeps unlocks and placements
working throughout. We tested the environment CA and policy key procedures together on a
live pool with a create every few seconds: no unlock and no placement failed.

A cell's lease lasts 60 minutes and renews 45 minutes in, so "one lease" below means:
wait until every cell has renewed (the verifier's log shows an accepted unlock for each
instance since the change), and an hour has passed before you retire anything old.

The verifier reads its configuration at start, so each step is an update of the
configuration followed by `deploy/verifier.sh deploy`. Export your receipt log first if
you need it kept: the log is held in memory and a new revision starts it empty
(`ListReceipts`; cells keep sending records for their running sandboxes).

## Environment CA

Your SDKs pin it, your verifier signs cell certificates with it, and the control plane
checks it when it calls a cell's `Drain`.

1. Make a new key version and a CA certificate from it:
   ```bash
   gcloud kms keys versions create --key=env-ca --keyring=clovelly-verifier --location=$REGION
   CLOVELLY_ACCESS_TOKEN=$(gcloud auth print-access-token) \
     verifier make-ca --kms-key .../cryptoKeys/env-ca/cryptoKeyVersions/2 --env $ENV > ca-2.pem
   ```
   The new CA's subject carries its version, so stacks that choose an issuer by subject
   tell the two apart.
2. Give every SDK a bundle of both, `cat ca-2.pem ca.pem > ca-both.pem`, as its `ca_bundle`,
   and tell us: we update the control plane's copy (`put-env --keep-token true`) with no
   change to your token. Nothing has changed for a running cell yet.
3. Point the verifier at the new CA: in the configuration, `ca.kms_key` is version 2,
   `ca.cert_pem` is `ca-2.pem`, and `ca.previous_cert_pem` holds the old certificate, so
   receipts from cells still on an old lease stay valid. Redeploy. New unlocks and every
   renewal now get certificates under the new CA.
4. After one lease, empty `ca.previous_cert_pem`, redeploy, change every SDK's bundle to
   `ca-2.pem`, tell us again, and disable the old key version.

Keep the old CA certificate with your receipts: `clovelly-receipt verify --ca` takes a
file with several certificates, and a receipt checks against the one that issued its
cell's certificate. The order matters only in that step 2 comes before step 3: an SDK that
trusts only the old CA refuses a cell on a new certificate, by design.

## Policy key

Cells verify every policy bundle against the keys the verifier names at each unlock and
renewal.

1. `gcloud kms keys versions create --key=policy ...`, and `verifier public-key` for the new
   version.
2. Set `policy_key_pem` to the old and new public keys, one PEM block after the other, and
   redeploy. Bundles are still signed by the old key.
3. After one lease every cell holds both. Sign each sub-environment's bundle with the new
   version, with a higher `version`, and redeploy. Cells take it within 60 seconds.
4. After another lease, set `policy_key_pem` to the new key alone, redeploy, and disable
   the old version.

Signing with the new key before step 3's wait would stop new sandboxes on any cell that has
not renewed: a cell refuses a bundle no key it knows opens, and says `POLICY_REFUSED`.

## Sub-environment DEKs

A sub-environment's DEK protects its credentials, templates and volumes, and is itself
wrapped by your `dek` KMS key.

- **Rotating the wrapping key** needs no downtime and touches no data. Create a new
  version of `dek`, make it primary, and re-encrypt the DEK:
  `gcloud kms decrypt ... | gcloud kms encrypt ...` into `subenvs.<name>.wrapped_dek`.
  Redeploy, and disable the old version when no configuration uses it.
- **Replacing the DEK itself** means replacing what it protects, since every stored
  ciphertext opens only under it. Create a new sub-environment with a new DEK, seal your
  credentials and upload your templates there, copy any volume you need by mounting the
  old and writing the new from a sandbox's output, move your workload, and delete the old
  sub-environment's objects (`DeleteTemplate`, `DeleteVolume`). Cells of a sub-environment
  hold its DEK only for a lease, so the old DEK leaves every cell within an hour of the
  old pool's last cell.

Revoking rather than rotating is simpler still: disable the `dek` key version and every
cell loses its keys within one lease ([threat model](threat-model.md)).

## Control-plane mTLS CA (ours)

Cells check the control plane's certificate on their report channel, and its client
certificate on `Drain`, against a CA baked into the measured image, so changing it is a
release you can see in the log:

1. A release whose image carries the old and the new CA in `image/control-plane-ca.pem`.
2. Pools move to it. Cells on the old release keep their schedule: each goes at its cap or
   sooner, and its replacement boots the new release.
3. When no cell of an older release is left, the control plane changes to certificates from
   the new CA. Your SDKs do not see this CA at all.
4. A later release carries the new CA alone.

## Control-plane API token

Ask us; `PutEnvironment` issues a new token and the previous one stops working at once.
