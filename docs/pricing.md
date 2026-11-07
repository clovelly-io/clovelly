<!-- Generated from the price book by `clovelly-admin pages`. Do not edit by hand. -->
# Pricing

> **These are staging figures for testing the billing mechanism. They are not Clovelly's prices; the prices are set before any organization outside staging exists.**

Clovelly bills cell-minutes: every minute from the moment we ask for a cell to the moment it is deleted, whatever ran on it. Nothing is billed per sandbox or per vCPU-second, because a cell is a dedicated confidential VM that runs only your sandboxes. What you pay is set by the settings you hold: the region, warm cells per zone, the idle window, sandbox sizes and timeouts.

## Cells

A cell-hour costs what its region costs: the region of the sub-environment it runs for ([regions.md](regions.md)). A create refused because the region is out of machines (`NO_CAPACITY`) bills nothing.

| Region | Machine type | Per cell-hour |
|---|---|---|
| `asia-southeast1` | `c3-standard-22` | $2.04 |
| `asia-southeast1` | `c3-standard-8` | $0.74 |
| `europe-west4` | `c3-standard-22` | $1.82 |
| `europe-west4` | `c3-standard-8` | $0.66 |
| `us-central1` | `c3-standard-22` | $1.65 |
| `us-central1` | `c3-standard-8` | $0.60 |

## Environment fee

$20.00 per environment per billing period, charged to your card at the start of the period and given to you as credit that pays for that period's cells. So a period costs the larger of the fee and your usage.

One plan. Enterprise is a conversation: write to us.

See [billing.md](billing.md) for how credit works and [limits.md](limits.md) for the limits.
