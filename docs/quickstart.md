# Your first sandbox

From nothing to a sandbox running your code, in under an hour. You need an account on your own cloud for your keys and
your verifier, a card for your Clovelly account, and the console at [app.clovelly.io](https://app.clovelly.io). You can
look around the console before any of this.

## 1. Create your environment (about 20 minutes)

Sign in, name your organization, and choose **New environment**. Signing up and all of this are free and need no card.

Your verifier is yours, and so are the keys it holds: nobody at Clovelly can read them. The console asks for an environment
id, then where your keys live, and shows the commands for that, which are the ones in [AWS](verifier-aws.md),
[Google Cloud](verifier-gcp.md) and [anywhere else](verifier-other.md). In short: one setup command makes three keys in your
key manager and a configuration, and prints your SDK token, once; you start two published containers next to your key
manager; you paste the verifier's address. Keep the token:

```bash
export CLOVELLY_VERIFIER_TOKEN=THE_TOKEN_SETUP_PRINTED
```

The console checks that your verifier answers and serves your CA, creates your environment and shows its first API key,
**once**. Keep the key secret: it can place sandboxes as you.

## 2. Turn on compute (5 minutes)

On the Billing tab, add a card: no cell boots until your organization has a card on file and credit above zero
([billing.md](billing.md)). Adding the card charges the environment fee, $49.00, as credit for the billing period, and
more credit comes in top-ups of at least $100.00. A cell-hour costs $0.95 to $1.20 by region, and egress beyond 10 GB per
cell-hour costs $0.15 per GB ([pricing.md](pricing.md)). On the Settings tab, add your sub-environment `main` and its pool, and choose the pool's region:
`us-central1`, `us-east4`, `us-west1`, `europe-west4` or `asia-southeast1`. The region is where its sandboxes run and where their traffic leaves
from, and it is set once ([regions.md](regions.md) says what it does not decide). The pool's defaults boot nothing until
a sandbox asks for a cell.

The console shows the API's address and CA. Point the SDK at them:

```bash
export CLOVELLY_API_URL=API_ADDRESS CLOVELLY_API_TOKEN=clv_MY_ENV_... CLOVELLY_API_CA=api-ca.pem
```

## 3. Install an SDK

```bash
pip install "clovelly @ https://github.com/clovelly-io/clovelly/archive/refs/heads/main.tar.gz#subdirectory=sdks/python"
```

The TypeScript SDK is in `sdks/typescript`: clone this repository, and `npm install ./sdks/typescript`.

## 4. Run a sandbox

The first create in an empty pool boots a cell, which takes two or three minutes; the
response says it was cold. After that, a create takes a fraction of a second.

```python
import clovelly

env = clovelly.Environment(VERIFIER_URL, "MY_ENV", "clovelly-out/MY_ENV/ca.pem")
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
restart your verifier (see [the verifier guide](verifier-deploy.md), "Publishing a policy").

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
