# What we store, and for how long

Everything we store for you is ciphertext under keys we do not hold.

| What | Where | Kept until |
|---|---|---|
| Sealed credentials | Our Cloud Storage, `<env>/<subenv>/credentials/` | You replace them or leave |
| Templates | Our Cloud Storage, `<env>/<subenv>/templates/` | You delete them (`DeleteTemplate`) or leave |
| Volumes | Our Cloud Storage, `<env>/<subenv>/volumes/` | You delete them (`DeleteVolume`) or leave |
| Environments, pools, cell records, billing counters | Our database; the columns hold no content | You leave |
| Receipts | **Never stored by us.** They go from the cell to your verifier's log | Your choice |
| Egress logs | **Never stored by us.** They come with a final receipt to your verifier | Your choice |
| Sandbox memory, files, traffic | Inside the cell only, on tmpfs | The sandbox's end, and at the latest the cell's 48-hour cap |

Our Cloud Storage and our database are in the United States, whatever region your sub-environment's cells run in:
a region decides where sandboxes run, not where this is kept ([regions.md](regions.md)).

Without your DEK, none of the stored ciphertext opens, for us or for anyone. Disable your
`dek` key and it is unreadable at once, wherever a copy might be.

## Quotas

An environment may have quotas on live cells, sandboxes and volume bytes. Reaching one
gives a typed refusal (`QUOTA_EXCEEDED`, `clovelly.QuotaExceeded`) naming the quota, at
once, rather than a wait. A cell draining for maintenance does not count against the cell
quota, so a drain never stops you. The volume quota is checked when a volume is mounted.

## Leaving

See [offboarding.md](offboarding.md).
