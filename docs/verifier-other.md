# The verifier with any other key manager, or on any other platform

A recipe for [the general sequence](verifier-deploy.md). The verifier reaches your keys through one small interface,
[the key helper](key-helper.md). If you have no helper for your key manager, write one: it is four operations and a
health check, and the reference code for
[Google Cloud KMS](../crates/key-helper/src/gcp.rs) and [AWS KMS](../crates/key-helper/src/aws.rs) is small enough to
copy. Any language will do; it is a separate container so that the verifier's image stays byte-identical for everyone.

The images, from the release page:

```bash
export KEYS_IMAGE=ghcr.io/clovelly-io/clovelly-keys@sha256:DIGEST VERIFIER_IMAGE=ghcr.io/clovelly-io/verifier@sha256:DIGEST
```

## 1. Run your helper

Start it as a container named `clovelly-keys-operator`, on an identity that may also encrypt, listening on
`127.0.0.1:8200`. Make three keys in your key manager (two P-256 signing keys and one that encrypts), named however your
helper understands.

## 2. Check it

Replace `CA_KEY`, `POLICY_KEY` and `DEK_KEY` with those names:

```bash
docker run --rm --platform linux/amd64 --network container:clovelly-keys-operator "$VERIFIER_IMAGE" check-keys http://127.0.0.1:8200 --sign-key CA_KEY --sign-key POLICY_KEY --dek-key DEK_KEY
```

Each check prints one line, and a failure names its reason; [key-helper.md](key-helper.md) lists them.

## 3. Make the configuration

For one sub-environment called `main`. This prints your SDK token, once:

```bash
mkdir -p clovelly-out/MY_ENV
docker run --rm --platform linux/amd64 --user "$(id -u):$(id -g)" --network container:clovelly-keys-operator -v "$PWD/clovelly-out/MY_ENV:/out" "$VERIFIER_IMAGE" init --env MY_ENV --subenv main --ca-key CA_KEY --policy-key POLICY_KEY --dek-key DEK_KEY --out /out
```

## 4. Start the two containers

On any platform: the verifier with `verifier.env` in its environment and `PORT` where your TLS terminator expects it, and
your helper beside it on the same loopback, on an identity that may sign, decrypt and read public keys and nothing else.
Exactly one instance, always on. Your platform must carry gRPC, HTTP/2 end to end, from a publicly trusted certificate
to the verifier.

On a machine of your own, [`deploy/compose.yaml`](../deploy/compose.yaml) does this: the verifier on `127.0.0.1:8080`, for
your own TLS terminator, and the helper in the verifier's network namespace. Set `KEYS_IMAGE` to your helper, or use a
reference helper with `KEYS_BACKEND=gcp` or `aws` on a machine with that cloud's role. It reads `clovelly-out/MY_ENV/`
through `CLOVELLY_OUT`:

```bash
curl -fsSL https://raw.githubusercontent.com/clovelly-io/clovelly/main/deploy/compose.yaml -o compose.yaml
CLOVELLY_OUT=clovelly-out/MY_ENV docker compose up -d
```
