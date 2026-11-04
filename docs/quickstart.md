# Your first sandbox

From nothing to a sandbox running your code, in under an hour. You need a Google Cloud
project with billing, and from Clovelly an account: the operator gives you the control
plane's address, its CA certificate and the release public key and release policy.

## 1. Deploy your verifier (about 40 minutes)

Follow [verifier-deploy.md](verifier-deploy.md) through step 3, in your own project:

```bash
deploy/verifier.sh setup MY_PROJECT us-central1 MY_ENV main
```

The verifier is yours, and so are the keys it holds: nobody at Clovelly can read them. Note
what the deploy printed (your verifier's URL) and `deploy/out/MY_ENV/ca.pem` (your
environment CA).

Choose an SDK token now, so your SDK can seal credentials and read your receipts, and put its
SHA-256 in the verifier's configuration before you deploy:

```bash
export CLOVELLY_VERIFIER_TOKEN=$(openssl rand -hex 32)
jq --arg h "$(printf %s "$CLOVELLY_VERIFIER_TOKEN" | shasum -a 256 | cut -d' ' -f1)" \
  '.sdk_token_sha256 = $h' deploy/out/MY_ENV/config.json > c && mv c deploy/out/MY_ENV/config.json
```

## 2. Create your environment (5 minutes)

Send the operator your verifier's URL, your environment id and `ca.pem`. You get back an API
token, the API address and its CA, and a pool for your sub-environment. Keep the token
secret: it can place sandboxes as you.

```bash
export CLOVELLY_API_URL=API_ADDRESS CLOVELLY_API_TOKEN=YOUR_TOKEN CLOVELLY_API_CA=api-ca.pem
```

## 3. Install an SDK

```bash
pip install ./sdks/python        # or: npm install ./sdks/typescript
```

## 4. Run a sandbox

The first create in an empty pool boots a cell, which takes two or three minutes; the
response says it was cold. After that, a create takes a fraction of a second.

```python
import clovelly

env = clovelly.Environment(VERIFIER_URL, "MY_ENV", "deploy/out/MY_ENV/ca.pem")
with env.sandbox("main", cpu=1, memory=2, timeout=900) as sb:
    print(sb.exec(["python3", "-c", "print('hello from the cell')"]).stdout.decode())
    receipt = sb.close()
print(receipt.final, receipt.exit_kind)
```

The SDK will not send a byte until the cell's certificate chains to your CA, and your
verifier issued that certificate only after checking the cell's attestation.

## 5. Give it a credential

Sandboxes never see real credentials. The verifier seals yours; the sandbox holds a
placeholder; the proxy in the cell swaps it on the way out, only to the destination you named.
The policy must allow that destination: sign a new policy bundle with your policy key and
redeploy (see [the verifier guide](verifier-deploy.md), "Updating", and the bundle's format
in `crates/common/src/bundle.rs`).

```python
env.put_credential("main", "openai", "sk-...", adapter="bearer", destination="api.openai.com")
with env.sandbox("main") as sb:
    sb.exec(["sh", "-c", 'curl -s -H "Authorization: Bearer $KEY" https://api.openai.com/v1/models'],
            env={"KEY": sb.cred("openai")})
```

## 6. Bring your own template

A template is the `.tar.gz` of a sandbox root. The SDK encrypts it under a key your verifier
issues; the control plane only ever stores ciphertext.

```python
tpl = env.upload_template("main", "my-template", "root.tar.gz")
with env.sandbox("main", template=tpl) as sb:
    ...
```

## 7. Read your receipts

Every sandbox ends with a receipt signed inside its cell, and it goes to your verifier, not to
us. `env.receipts("main")` lists them; `clovelly-receipt verify` checks one offline
([the SDK README](../sdks/python/README.md), "Receipts"). `env.egress_log(sandbox_id)` gives
the sandbox's outbound connections, whose hash is in its receipt.

## Where to go next

- [Evidence pack](evidence-pack.md): what you can check, and how.
- [Key rotation](key-rotation.md), [retention](retention.md), [leaving](offboarding.md).
- The SDK READMEs list every call and every typed error.
