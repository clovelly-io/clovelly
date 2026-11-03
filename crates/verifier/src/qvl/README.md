# qvl: our port of Intel's quote verification, for TDX

SPEC.md decision 4 names `dcap-qvl` for quote verification, with a port of Intel's QVL
logic as the fallback if its licence fails the allowlist. It does: `dcap-qvl` 0.7.0
depends on `parity-scale-codec`, which depends on `const_format` and `konst` (Zlib).
This directory is the fallback. It is written for review against Intel's source,
function by function.

## What it was ported from

**Intel QVL**, the `confidential-computing.tee.dcap.qvl` repository at commit
`d12717e3f1f2ab81313f88001fd902b5ef5f9c8c`, the QVL that Intel's
`confidential-computing.tee.dcap` release **DCAP_1.27.101** pins as its
`QuoteVerification/QVL` submodule. Paths below are under
`Src/AttestationLibrary/src/`. The step numbers (4.1.2.x) are the ones Intel's source
comments carry.

| Ours | Intel QVL | What |
|---|---|---|
| `quote.rs` `SignedQuote::parse` | `QuoteVerification/Quote.cpp`, `QuoteStructures.cpp` | v4 and v5 TDX quote layout: header, TD 1.0/1.5 report body, ECDSA signature data, certification data type 6 (QE report) wrapping type 5 (PEM PCK chain). |
| `chain.rs` `verify` | `Verifiers/PckCertVerifier.cpp` (4.1.2.4), `CertVerification/CertificateChain.cpp`, `Verifiers/TCBSigningChain.cpp` | Each certificate signed by the next (ECDSA P-256 SHA-256), issuers are CAs, all valid now, the chain ends at the pinned root. |
| `mod.rs` `verify_signatures`, CN checks | `Verifiers/PckCertVerifier.cpp` | PCK subject contains "SGX PCK Certificate", its issuer "CA". |
| `mod.rs` `verify_signatures`, QE report | `Verifiers/QuoteVerifier.cpp` 4.1.2.5.13-14 | QE report signed by the PCK key; its REPORTDATA is SHA-256(attestation key ‖ QE auth data). |
| `mod.rs` `verify_signatures`, quote | `Verifiers/QuoteVerifier.cpp` (after 4.1.2.5.16) | Header and body signed by the attestation key. |
| `mod.rs` `signed_document`, `current` | `Verifiers/TCBInfoVerifier.cpp`, `Verifiers/EnclaveIdentityVerifier.cpp` | TCB info and QE identity signed by the TCB signing certificate, chained to the root, not expired. |
| `mod.rs` `verify_signatures`, FMSPC and PCE id | `Verifiers/QuoteVerifier.cpp` 4.1.2.5.10-11 | TCB info is TDX (`id` "TDX", version 3 or later) and matches the PCK's FMSPC and PCE id. QE identity is `TD_QE` (4.1.2.5.15). |
| `pck.rs` `PckInfo::of` | `AttestationParsers/src/X509/PckCertificate.cpp`, `X509/Tcb.cpp` | The SGX extension: PPID, FMSPC, PCE id, TCB component SVNs 1-16, PCESVN. |
| `mod.rs` `module_identity` | `Verifiers/QuoteVerifier.cpp` 4.1.2.5.12, `Verifiers/Checks/TdxModuleCheck.cpp` | TDX module identity `TDX_<version>` for a non-zero module version, else `tdxModule`; MRSIGNERSEAM equal; every SEAMATTRIBUTES byte zero and equal to Intel's (no mask, as Intel). |
| `mod.rs` `qe_identity` | `Verifiers/EnclaveReportVerifier.cpp` 4.1.2.9.5-8 | (MISCSELECT & mask) and (ATTRIBUTES & mask) equal the identity's values; MRSIGNER if present; ISVPRODID. |
| `mod.rs` `evaluate` | `Verifiers/Checks/EvaluateTcb.cpp` `tdxEvaluateTCB` (4.1.2.5.2) | First TCB level met by the SGX components, PCESVN and TDX components (skipping indexes 0 and 1 for a non-zero module version); the module's TCB level by ISVSVN; the QE's level by ISVSVN; each structure's allowed statuses. |
| `collateral.rs` `TcbStatus::converge` | `EvaluateTcb.cpp` `convergeTcbStatuses` | Out-of-date and revoked components override the platform status. |
| `mod.rs` `tcb_status`, `collateral.rs` `TcbStatus::relaunch` | `Verifiers/Checks/TcbLevelCheck.cpp` 4.1.2.5.19-20, `Verifiers/Checks/TDRelaunchCheck.cpp` | Launch and, for TD 1.5, current TCB evaluated separately, then `checkForRelaunch`. |

Revocation (the PCK and intermediate CRLs, `PckCertVerifier.cpp` and
`Verifiers/PckCrlVerifier.cpp`, QuoteVerifier 4.1.2.5.7-8) is not here: it is the
verifier's check 2 (`../verifier.rs`, `collateral_check`). That code checks both CRLs'
signatures and currency, that each CRL's issuer is the certificate's issuer, and that
neither revokes the chain. Check 2 runs first; a chain is only verified with usable
CRLs.

We also read `dcap-qvl` 0.7.0 (MIT, Copyright Phala Network), which ports the same
logic to Rust, to cross-check our reading of Intel's. No code was copied from it.

## Where we differ from Intel QVL

Stricter:
- The QE report's upper 32 REPORTDATA bytes must be zero (Intel compares only the first
  32 bytes).
- TCB info and QE identity must be issued no later than `now` as well as not past
  `nextUpdate`.
- Any TCB level with fewer or more than 16 SGX or TDX components fails evaluation.

Simpler, with the same result for GCE TDs:
- Collateral validity is judged at the verifier's clock (`now`), not at a separate
  expiration date.
- Advisory ids are concatenated platform, QE, module, as Intel, with duplicates kept.

## What is not covered

- SGX quotes, quote version 3, and certification data other than type 6 wrapping a type
  5 PEM chain. GCE TDX quotes are v4 with type 6/5.
- Attestation keys other than ECDSA P-256.
- The QVE (enclave-hosted verification) and supplemental data.
- TCB dates (`tcbDate`) and date-based TCB recovery policies; the verifier's policy
  judges only the status and advisory ids (check 3).
- Choosing a TCB evaluation data number: we use what PCS serves by default
  (`update=standard`); `tcbEvaluationDataNumber` is parsed but no minimum is enforced.
- PCK certificate fields Intel exposes as supplemental data (dynamic platform, cached
  keys, SMT): parsed by neither us nor policy.

## Tests

- `../../tests/qvl.rs`: a real GCE TDX quote with Intel's collateral for its platform
  verifies to Intel's root with status `UpToDate`; a changed report byte, another root,
  edited TCB info and collateral past `nextUpdate` are refused.
- The evidence corpus (in our private test suite), with quotes re-signed under a test root
  and crafted collateral (revoked PCK, stale CRL) alongside genuine ones.
