# Leaving

When you leave we delete everything of yours that we hold within 30 days of your request,
and send you a deletion receipt signed by our key. In practice it takes minutes. Your
verifier, your KMS keys and your receipt log were always in your own project: delete them
when you choose. Destroying your `dek` key versions is the step that makes any copy of
your ciphertext, anywhere, unreadable, so we suggest doing it whatever we say we did.

## What we do

1. Your API token stops working, and your pools go, so nothing new starts.
2. Your cells are deleted, with their forwarding rules. A sandbox still running dies with
   its cell. Close your sandboxes first: its last-will receipt in your log says `cell_lost`
   otherwise.
3. Every object under your environment's prefix in our Cloud Storage is deleted: sealed
   credentials, templates, volumes.
4. Every row of yours in our database is deleted, in one transaction.
5. We list your prefix again; the count must be zero, and it goes in the receipt.

## The deletion receipt

`deletion-receipt.json` is canonical JSON: your environment id, when it started and
finished, the cells deleted, the number and bytes of the objects deleted, the SHA-256 over
their sorted names (each followed by a newline), the objects remaining (zero), and the rows
deleted per table. `deletion-receipt.jws` is its signature, a compact JWS with ES256, by
our deletion-receipt key in Cloud KMS. Our public key is in the
[evidence pack](evidence-pack.md).

To check it with nothing of ours but the public key: the JWS's payload, base64url-decoded,
equals `deletion-receipt.json`, and its signature verifies over `header.payload` with
`openssl dgst -sha256 -verify`, after converting `r||s` to DER.

We keep your month's billing export, which names cell ids and times and nothing else, for
as long as tax law asks. Our Cloud Logging holds the control plane's own operational lines
(which name your environment and carry no content) for 30 days.

## What you do

Export your receipt log if you need it, then stop your verifier and destroy your three keys in your key manager, which is
what makes your data unreadable. On Google Cloud, with the recipe's names:

```bash
for k in MY_ENV-env-ca MY_ENV-policy MY_ENV-dek; do
  for v in $(gcloud kms keys versions list --key=$k --keyring=clovelly-verifier --location=$REGION \
      --filter='state=ENABLED OR state=DISABLED' --format='value(name.basename())'); do
    gcloud kms keys versions destroy "$v" --key=$k --keyring=clovelly-verifier --location=$REGION
  done
done
gcloud run services delete verifier --region=$REGION
```

On AWS, with the recipe's names (KMS destroys a key after a waiting period, 30 days here):

```bash
for k in env-ca policy dek; do
  aws kms schedule-key-deletion --pending-window-in-days 30 --key-id alias/clovelly-MY_ENV-$k
done
aws cloudformation delete-stack --stack-name clovelly-verifier-MY_ENV
```

Cloud KMS keeps a key's name forever and destroys its material after the scheduled
destruction period (30 days by default).
