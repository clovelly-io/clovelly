<!-- Generated from the price book by `clovelly-admin pages`. Do not edit by hand. -->
# Pricing

Clovelly bills cell-minutes: every minute from the moment we ask for a cell to the moment it is deleted, whatever ran on it. Nothing is billed per sandbox or per vCPU-second, because a cell is a dedicated confidential VM that runs only your sandboxes. What you pay is set by the settings you hold: the region, warm cells per zone, the idle window, sandbox sizes and timeouts.

## Cells

A cell-hour costs what its region costs: the region of the sub-environment it runs for ([regions.md](regions.md)). A create refused because the region is out of machines (`NO_CAPACITY`) bills nothing.

| Region | Machine type | Per cell-hour |
|---|---|---|
| `asia-southeast1` | `c3-standard-22` | $3.30 |
| `asia-southeast1` | `c3-standard-8` | $1.20 |
| `asia-southeast1` | `c3-standard-88` | $13.20 |
| `europe-west4` | `c3-standard-22` | $2.8875 |
| `europe-west4` | `c3-standard-8` | $1.05 |
| `europe-west4` | `c3-standard-88` | $11.55 |
| `us-central1` | `c3-standard-22` | $2.6125 |
| `us-central1` | `c3-standard-8` | $0.95 |
| `us-central1` | `c3-standard-88` | $10.45 |
| `us-east4` | `c3-standard-22` | $2.8875 |
| `us-east4` | `c3-standard-8` | $1.05 |
| `us-east4` | `c3-standard-88` | $11.55 |
| `us-west1` | `c3-standard-22` | $2.8875 |
| `us-west1` | `c3-standard-8` | $1.05 |
| `us-west1` | `c3-standard-88` | $11.55 |

## Per sandbox

A full cell spreads its cell-hour over its sandboxes. A `c3-standard-88` in `us-central1` ($10.45 a cell-hour) holds 87 sandboxes of 1 vCPU, about $0.12 a sandbox-hour when full. A sub-environment whose policy sets `cpu_share` shares its cells' CPUs among its own sandboxes, each keeping its CPU as a cap ([verifier-deploy.md](verifier-deploy.md#sharing-cpu-among-a-sub-environments-sandboxes)): at 3 the same cell holds 261 sandboxes of 1 vCPU and 1 GiB, about $0.04 a sandbox-hour. Memory is never shared, so a cell holds no more sandboxes than its 342 GiB allow: 171 of 2 GiB at any factor, about $0.06 a sandbox-hour; sharing pays off only for sandboxes of about 4/F GiB or less (1.3 GiB at 3, 1 GiB at 4).

## Egress

What your sandboxes send out of a cell is metered: the egress proxy counts every byte it sends toward a destination your policy allows, inside the cell, where no sandbox can see or change the count. Responses coming back are not counted, and neither is the cell's own traffic to your verifier and to us.

Each cell-hour includes 10 GB, pooled across a sub-environment's cells for each UTC day. Beyond that, egress is $0.15 per GB (10^9 bytes), billed at the end of the day with the day's cell-minutes. A sub-environment that ran 24 cell-hours in a day sends 240 GB that day before any traffic is billed.

## Environment fee

$49.00 per environment per billing period, charged to your card at the start of the period and given to you as credit that pays for that period's cells and egress. So a period costs the larger of the fee and your usage. More credit is bought in top-ups of at least $100.00.

One plan, no free tier and no trial. Enterprise is a conversation: write to us.

See [billing.md](billing.md) for how credit works and [limits.md](limits.md) for the limits.
