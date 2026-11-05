# Rotating keys

Every key here is yours and lives in your key manager, except the control-plane mTLS CA, which is ours and rotates as a
release. Each procedure below keeps unlocks and placements working throughout. We tested the environment CA and policy key
procedures together on a live pool with a create every few seconds: no unlock and no placement failed.

A cell's lease lasts 60 minutes and renews 45 minutes in, so "one lease" below means: wait until every cell has renewed (the
verifier's log shows an accepted unlock for each instance since the change), and an hour has passed before you retire
anything old.

The verifier reads its configuration at start, so each step is a change to the configuration (`CLOVELLY_CONFIG`) followed
by a restart of your deployment. Export your receipt log first if you need it kept: the log is held in memory and a restart
starts it empty (`ListReceipts`; cells keep sending records for their running sandboxes).

The commands below reach your keys through a helper on your own login, which may do what the running one cannot:
`verifier` as a container on its loopback, `--network container:clovelly-keys-operator`, the way each recipe shows it. How you
make a new key or key version is your key manager's own command. Names are whatever your helper understands.

Add any new key's name to the keys your running helper serves, `CLOVELLY_KEYS_ALLOW` for the reference helpers, and restart
before you point the verifier at it.

## Environment CA

Your SDKs pin it, your verifier signs cell certificates with it, and the control plane checks it when it calls a cell's
`Drain`.

1. Make a new signing key or version, and a CA certificate from it:
   ```bash
   docker run --rm --platform linux/amd64 --network container:clovelly-keys-operator "$VERIFIER_IMAGE" make-ca --key NEW_CA_KEY --env MY_ENV --generation 2 > ca-2.pem
   ```
   `--generation` goes into the new CA's subject, so stacks that choose an issuer by subject tell the two apart.
2. Give every SDK a bundle of both, `cat ca-2.pem ca.pem > ca-both.pem`, as its `ca_bundle`, and tell us: we update the control
   plane's copy (`put-env --keep-token true`) with no change to your token. Nothing has changed for a running cell yet.
3. Point the verifier at the new CA: in the configuration, `ca.key` is the new key, `ca.cert_pem` is `ca-2.pem`, and
   `ca.previous_cert_pem` holds the old certificate, so receipts from cells still on an old lease stay valid. Restart. New
   unlocks and every renewal now get certificates under the new CA.
4. After one lease, empty `ca.previous_cert_pem`, restart, change every SDK's bundle to `ca-2.pem`, tell us again, and disable the
   old key.

Keep the old CA certificate with your receipts: `clovelly-receipt verify --ca` takes a file with several certificates, and a
receipt checks against the one that issued its cell's certificate. The order matters only in that step 2 comes before step 3:
an SDK that trusts only the old CA refuses a cell on a new certificate, by design.

## Policy key

Cells verify every policy bundle against the keys the verifier names at each unlock and renewal.

1. Make a new signing key or version, and read its public key: `verifier public-key --key NEW_POLICY_KEY`.
2. Set `policy_key_pem` to the old and new public keys, one PEM block after the other, and restart. Bundles are still signed by
   the old key.
3. After one lease every cell holds both. Sign each sub-environment's bundle with the new key, with a higher `version`
   (`verifier sign --key NEW_POLICY_KEY --detached < bundle.json`), and restart. Cells take it within 60 seconds.
4. After another lease, set `policy_key_pem` to the new key alone, restart, and disable the old one.

Signing with the new key before step 3's wait would stop new sandboxes on any cell that has not renewed: a cell refuses a bundle
no key it knows opens, and says `POLICY_REFUSED`.

## Sub-environment DEKs

A sub-environment's DEK protects its credentials, templates and volumes, and is itself wrapped by your `dek` key.

- **Rotating the wrapping key** needs no downtime and touches no data. Create a new version of `dek` and make it primary
  (or a new key), and wrap the DEK again, putting what it prints in `subenvs.<name>.wrapped_dek`:
  ```bash
  docker run -i --rm --platform linux/amd64 --network container:clovelly-keys-operator "$VERIFIER_IMAGE" rewrap --key DEK_KEY < wrapped-dek.b64
  ```
  Restart, and disable the old version when no configuration uses it.
- **Replacing the DEK itself** means replacing what it protects, since every stored ciphertext opens only under it. Create a new
  sub-environment with a new DEK, seal your credentials and upload your templates there, copy any volume you need by mounting the
  old and writing the new from a sandbox's output, move your workload, and delete the old sub-environment's objects
  (`DeleteTemplate`, `DeleteVolume`). Cells of a sub-environment hold its DEK only for a lease, so the old DEK leaves every cell
  within an hour of the old pool's last cell.

Revoking rather than rotating is simpler still: disable the `dek` key and every cell loses its keys within one lease
([threat model](threat-model.md)).

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
