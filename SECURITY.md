# Security policy

Clovelly is a confidential sandbox runtime, so a vulnerability report is the most
useful contribution this repository can receive.

## Reporting a vulnerability

Report privately through GitHub: open the Security tab of this repository and choose
"Report a vulnerability". Do not open a public issue for anything that could let a
sandbox reach what it should not, let the provider see customer content, or let a
cell unlock without a valid attestation.

We acknowledge reports within three working days. A confirmed high or critical finding
in the trusted base ships as a security release with a 24-hour notice window; earlier
releases then expire seven days after that window ends, so every customer's verifier
stops accepting them.

## Scope

Everything in this repository: the cell image, the cell agent and egress proxy, the
verifier, the SDKs and the protocol definitions. The hosted platform is in scope for
reports as well; say so in the report and we will route it.

## What we publish

Each release's measurements, build recipe and provenance are in the public Sigstore
Rekor log, and REPRODUCE.md shows how to rebuild a release and compare.
