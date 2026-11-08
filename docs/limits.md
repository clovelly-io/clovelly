<!-- Generated from the price book by `clovelly-admin pages`. Do not edit by hand. -->
# Limits

Each environment starts with these quotas. A call at a quota gets the typed error `QUOTA_EXCEEDED` at once, never a queue. To raise one, write to us.

| Limit | Default |
|---|---|
| Environments per organization | 10 |
| Cells per environment | 5 |
| Sandboxes per environment | 70 |
| Volume ciphertext per environment | 100 GiB |

Sandboxes run for at most 24 hours; a cell is recycled at most 48 hours after it unlocks. New organizations are limited to 5 a day; past that, sign-ups go on a waitlist and we email you when there is room.

A `c3-standard-88` cell holds 87 sandboxes of the default size (1 vCPU), more than the default sandbox quota: write to us for a higher one before a pool fills such a cell.
