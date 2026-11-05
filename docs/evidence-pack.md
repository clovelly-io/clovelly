# Evidence pack

What you need to check our claims yourself, or to hand to someone who will. Everything here
is reachable from this repository; `clovelly.io` serves the same pages.

| Item | Where | What it shows |
|---|---|---|
| Measurement set | [Releases](https://github.com/clovelly-io/clovelly/releases): each release's `fragment.json` and `entry.json` | What a genuine cell of that release measures, logged in Sigstore's Rekor |
| Rebuilding a release | [REPRODUCE.md](../REPRODUCE.md) | How to get the same measurements from this source, alone |
| The key helper | [key-helper.md](key-helper.md) | The one interface between your verifier and your keys, and its conformance suite |
| Verifier deployment guide | [verifier-deploy.md](verifier-deploy.md) | Running your own verifier, on your platform, with your keys in your key manager |
| Threat model | [threat-model.md](threat-model.md) | What this defends against, and what it does not |
| Receipt tool | [`crates/receipt-tool`](../crates/receipt-tool) | Checks a receipt offline: signature, chain to your CA, measurements |
| Static egress addresses | [static-egress-ips.md](static-egress-ips.md) | The addresses your sandboxes' traffic comes from |
| Key rotation | [key-rotation.md](key-rotation.md) | How each key changes without downtime |
| Retention and quotas | [retention.md](retention.md) | What we store, for how long |
| Offboarding | [offboarding.md](offboarding.md) | How you leave, and the signed receipt you get |
| Deletion-receipt key | [deletion-receipts.pub.pem](deletion-receipts.pub.pem) | Checks that receipt |
| Security policy | [SECURITY.md](../SECURITY.md) | How to report a vulnerability, and our response targets |
| Status | `status.clovelly.io` | The control plane's state, from outside it |
| Red-team report | [red-team-report.md](red-team-report.md) (added when the test closes) | An internal report: an independent agent session with no access to our private code attacked a staging environment for at least 24 hours of session time |
| SOC 2 control mapping | [soc2-control-mapping.md](soc2-control-mapping.md) (added on sign-off) | Each control, its owner and where its evidence lives. A mapping, not an audit: we have no auditor's report yet |

## What is not here

There is no independent signer and no outside audit. The claim is "you can check", and this
page is how.
