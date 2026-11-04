<!-- Generated from the price book by `clovelly-admin pages`. Do not edit by hand. -->
# Limits

> **These are staging figures for testing the billing mechanism. They are not Clovelly's prices; the prices are set before any organization outside staging exists.**

Each environment starts with these quotas. A call at a quota gets the typed error `QUOTA_EXCEEDED` at once, never a queue. To raise one, write to us.

| Limit | Default |
|---|---|
| Environments per organization | 10 |
| Cells per environment | 5 |
| Sandboxes per environment | 70 |
| Volume ciphertext per environment | 100 GiB |

Sandboxes run for at most 24 hours; a cell is recycled at most 48 hours after it unlocks. New organizations are limited to 5 a day; past that, sign-ups go on a waitlist and we email you when there is room.
