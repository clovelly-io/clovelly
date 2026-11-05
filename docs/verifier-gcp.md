# The verifier on Google Cloud

A recipe for [the general sequence](verifier-deploy.md): your keys in Cloud KMS, the verifier on Cloud Run with
the key helper as its sidecar. You need a Google Cloud project with billing, `gcloud` logged in as someone who may
enable APIs and create service accounts, KMS keys, an Artifact Registry repository and a Cloud Run service, and a
container runtime. About 15 minutes.

[`deploy/verifier.sh`](../deploy/verifier.sh) is a thin wrapper, so read it if you want to do these steps by hand.

The images, from the release page:

```bash
export KEYS_IMAGE=ghcr.io/clovelly-io/clovelly-keys@sha256:DIGEST VERIFIER_IMAGE=ghcr.io/clovelly-io/verifier@sha256:DIGEST
```

The wrapper:

```bash
curl -fsSL https://raw.githubusercontent.com/clovelly-io/clovelly/main/deploy/verifier.sh -o verifier.sh && chmod +x verifier.sh
```

The keys and the configuration, for one sub-environment called `main`. This prints your SDK token, once:

```bash
./verifier.sh init MY_PROJECT us-central1 MY_ENV main
```

The two containers. This prints your verifier's address:

```bash
./verifier.sh deploy MY_PROJECT us-central1 MY_ENV verifier
```

## What it made

- Key ring `clovelly-verifier`, with three keys named after your environment: `MY_ENV-env-ca` and `MY_ENV-policy`
  (EC P-256, signing) and `MY_ENV-dek` (symmetric).
- Service account `clovelly-verifier`, which may sign with the first two and read their public keys, and decrypt
  with the third, each by a grant on that key, and nothing else.
- Artifact Registry repository `clovelly-ghcr`, a remote of `ghcr.io`: Cloud Run cannot pull from there directly.
  The digest is the same.
- Cloud Run service `verifier`: the verifier and `clovelly-keys serve gcp`, sharing loopback, one instance and always
  on (`minScale` and `maxScale` both 1). HTTP/2 end to end; no invoker IAM check, because cells prove themselves
  by attestation and not by a Google identity.
- `clovelly-out/MY_ENV/`: the configuration ([what is in it](verifier-deploy.md#the-sequence)).

Your own login made the keys, and it leaves them: no key material leaves Cloud KMS, and the running service
account cannot create, delete, disable or re-key anything. To prove that to yourself, run this as that account (a
Cloud Run job does it):

```text
clovelly-keys check-role gcp --sign-key CA_KEY_VERSION --dek-key DEK_KEY
```

## Checking the helper from your machine

The same image serves the same keys on your login, for `verifier check-keys`, `verifier sign` and the rotations in
[key-rotation.md](key-rotation.md):

```bash
docker run -d --name clovelly-keys-operator --platform linux/amd64 --env-file clovelly-out/MY_ENV/keys.env -e CLOVELLY_ACCESS_TOKEN="$(gcloud auth print-access-token)" "$KEYS_IMAGE" serve gcp
```

```bash
docker run --rm --platform linux/amd64 --network container:clovelly-keys-operator "$VERIFIER_IMAGE" check-keys http://127.0.0.1:8200 --sign-key CA_KEY_VERSION --sign-key POLICY_KEY_VERSION --dek-key DEK_KEY
```

The names are in `clovelly-out/MY_ENV/keys.env`. Remove the helper when you are done: `docker rm -f clovelly-keys-operator`.
