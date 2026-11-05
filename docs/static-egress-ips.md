# Static egress addresses

A sandbox's outbound traffic, through the in-cell proxy, leaves through Cloud NAT from these
reserved addresses, so a destination can allowlist them.

| Region | Addresses |
|---|---|
| us-central1 | `34.9.161.117`, `34.136.66.133` |

These are the addresses of our staging environment, the only one running today; a
production region's addresses will be added here before it takes traffic. Traffic to Google
APIs and services takes Google's private path and does not come from these addresses.

Cells reach a verifier outside Google from these addresses too. You may allowlist them in front of your verifier; cells
still authenticate by attestation and by nothing about the network.
