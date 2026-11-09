# Regions

Each sub-environment runs in one region, which you choose when you make its pool. Its cells, and so its sandboxes,
run in that region, and their traffic to the internet leaves from that region's two static addresses
([static-egress-ips.md](static-egress-ips.md)).

| Region | Where | Zones |
|---|---|---|
| `us-central1` | Iowa, USA | `us-central1-a`, `us-central1-b`, `us-central1-c` |
| `us-east4` | Ashburn, Virginia, USA | `us-east4-a`, `us-east4-c` |
| `us-west1` | The Dalles, Oregon, USA | `us-west1-a`, `us-west1-b` |
| `europe-west4` | Eemshaven, Netherlands | `europe-west4-a`, `europe-west4-b`, `europe-west4-c` |
| `asia-southeast1` | Jurong West, Singapore | `asia-southeast1-a`, `asia-southeast1-b`, `asia-southeast1-c` |

A zone is in the list once a cell of the current release has booted there and its firmware measurement has been
reviewed; the release policy's `allowed_zones` names exactly these zones, and your verifier refuses a cell from any
other. `us-east4` and `us-west1` have two zones each: their other zones do not take a confidential (TDX) VM, so a
stockout in both of a region's two zones is a region out.

## Reaching your cells

Your SDK reaches a sandbox through one address in its region, the relay in front of that region's cells. Cells have
no address of their own on the internet. The SDK dials the relay with the cell's own name,
`<instance>.<zone>.<subenv>.<env>.cells.clovelly.internal`, as the TLS server name. The relay forwards the
connection to that cell without decrypting it, and the SDK checks the cell's certificate against your environment CA
as it always has. If your network allows outbound connections only to listed addresses, allow TCP 443 to your
regions' relays:

| Region | Relay address |
|---|---|
| `us-central1` | `35.254.84.14` |
| `europe-west4` | `34.187.43.227` |
| `us-east4` | `34.182.224.43` |
| `us-west1` | `136.87.77.46` |
| `asia-southeast1` | `34.87.53.119` |

The relay learns which cell each connection is for and how many bytes go each way, and nothing else. See the
[threat model](threat-model.md#the-relay-in-front-of-the-cells).

## Choosing one

```python
env.put_pool("bank-a", region="europe-west4")
```

```ts
await env.putPool("bank-a", { region: "europe-west4" });
```

Or on the console's Settings tab, when you add the sub-environment's pool. A name not in the list is refused with
`UNKNOWN_REGION` (`UnknownRegion` in both SDKs), which carries the list. The region is set once: a sub-environment
never moves, and another region is another sub-environment, with its own keys, as any sub-environment has.

## When machines run out

You choose the region; we choose the zone. The pool uses every zone of the region in the list, and when one zone has
no machines, new cells go to the others and you see nothing.

When every zone of the region has refused a new cell, and no cell of your pool can take the sandbox, the create
fails at once with `NO_CAPACITY` (`NoCapacity` in both SDKs), naming the region and how many seconds until we try
those zones again. Nothing is billed for a refused cell. We never queue the sandbox and never move it to another
region, because either would hide where your code runs: if you want a fallback, make a sub-environment in a second
region and create the sandbox there.

## What a region decides, and what it does not

A region decides where your sandboxes run, in memory and on the cell, and where their outbound traffic leaves from.

It is not a data-residency promise. These stay where they are whatever region you choose:

- your templates' and volumes' ciphertext, in our storage in the United States, which a cell in another region
  fetches across regions (it is encrypted under your keys, and we cannot read it);
- the control plane and its records (environments, pools, cells, placements, billing), in the United States;
- your receipts, in your verifier, wherever you run it;
- your keys, in your key manager, wherever it is.

Prices differ by region: see [pricing.md](pricing.md).
