# Static egress addresses

A sandbox's outbound traffic, through the in-cell proxy, leaves through Cloud NAT from its
region's two reserved addresses, so a destination can allowlist them. A cell uses the
addresses of the region it runs in ([regions.md](regions.md)); to allowlist every region,
allowlist all ten.

| Region | Addresses |
|---|---|
| us-central1 | `35.253.209.53`, `34.132.194.96` |
| us-east4 | `136.107.122.207`, `8.234.139.153` |
| us-west1 | `8.231.162.102`, `136.70.16.162` |
| europe-west4 | `34.147.94.68`, `34.12.127.221` |
| asia-southeast1 | `34.21.199.164`, `34.21.184.141` |

A region's addresses are added here before it takes traffic, and an address is never removed
while a region uses it. Traffic to Google APIs and services takes Google's private path and does
not come from these addresses.

Cells reach a verifier outside Google from these addresses too. You may allowlist them in front of your verifier; cells
still authenticate by attestation and by nothing about the network.
