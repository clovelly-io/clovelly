<!-- Generated from the price book by `clovelly-admin pages`. Do not edit by hand. -->
# Billing

Clovelly is prepaid: usage comes out of a balance of credit, and we are paid before a cell boots.

## A card before the first cell

Signing up, the console, deploying your verifier and creating an environment are free and need no card. No cell boots until your organization has a card on file and credit above zero. There is no free compute.

## Credit

Three kinds, drawn soonest-expiring first:

- **Period credit**: the environment fee, charged when your card goes on file and at the start of each billing period. It pays only for that period and expires when it ends.
- **Bought credit**: top-ups and auto-recharge, at least $100.00, expiring 12 months after payment. It is never refunded.
- **Operator credit**: granted by us, expiring 12 months after it is granted.

A billing period runs from the UTC day your card went on file to the same day the next month, with no proration. Every charge is one Stripe invoice paid at once; there is no invoice at the end of a period. Receipts are in Stripe's portal, reached from the Billing tab.

## At zero

At zero credit, `PlaceSandbox` is refused with the typed error `CREDIT_EXHAUSTED` (`CreditExhausted` in both SDKs), pools boot nothing and idle cells recycle on their window. **Running sandboxes finish to their timeout**: we never make a judgement call on your sandbox's data from our ledger. The balance can go below zero by what those cells run up, and that debt comes off your next credit. Credit added resumes placements within one minute.

You get one email when the balance falls below your low-balance level ($10.00 until you set one) and one when it reaches zero, once each time it happens. Auto-recharge is off until an owner turns it on; at most one recharge is unpaid at a time.

## A failed charge

A failed environment fee pauses placements 72 hours after the failure, until it is paid. A failed top-up or recharge pauses nothing by itself. Owners and admins are emailed Stripe's page to pay it, and Stripe retries it too.

## Your usage

The Usage tab shows cell-minutes and egress by sub-environment, its region and day, and the month's cell-minutes, egress and environment fee as separate lines; it exports the month's bill as CSV. Egress is billed per GB beyond the allowance of 10 GB per cell-hour, at $0.15 ([pricing.md](pricing.md)). `ExportBilling` returns the same bill through the API, and credit is drawn from exactly that bill, to the cent.
