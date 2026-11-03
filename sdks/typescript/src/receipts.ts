// Receipts (SPEC.md "Receipt"): what a cell signs for each sandbox, and the customer's
// receipt log at their own verifier. The SDK exposes the pieces a receipt is checked with
// (the canonical JSON that was signed, the signature and the cell certificate) but does not
// verify them: the public receipt tool does, from the receipt, the certificate's chain to
// the environment CA and the published measurement set.
import { createHash } from "node:crypto";
import * as grpc from "@grpc/grpc-js";
import { EgressLogMismatch, protocolError } from "./errors.js";
import * as pb from "./proto.js";
import type { SandboxId } from "./sandbox.js";

/** How a sandbox ended (the receipt's `exit.kind`). */
export type ExitKind = NonNullable<(typeof pb.EXIT_KINDS)[pb.WireExitKind]>;

/** A JSON value, as `JSON.parse` returns it. */
export type Json = string | number | boolean | null | readonly Json[] | JsonObject;

/** A JSON object, as `JSON.parse` returns it. */
export type JsonObject = { readonly [key: string]: Json };

/** A sandbox's signed receipt, as its cell returned it: interim while it runs, final once it has ended. */
export interface Receipt {
  /** The receipt in JCS canonical form: exactly the bytes `signature` covers. */
  readonly json: Buffer;
  /** ECDSA P-256 with SHA-256 over `json` by the cell key, `r || s` (64 bytes). */
  readonly signature: Buffer;
  /** The signing cell's certificate (DER), which chains to the environment CA. */
  readonly cellCert: Buffer;
  /** The sandbox has ended; no later receipt will follow. */
  readonly final: boolean;
  /** Undefined only if the cell left it unspecified. */
  readonly exitKind: ExitKind | undefined;
  /** `json`, parsed. */
  readonly doc: JsonObject;
  /** @deprecated `doc`, under its name before phase 4. */
  readonly data: JsonObject;
}

/** One sandbox's record in the customer's receipt log: the latest receipt the log received for it. */
export interface LoggedReceipt {
  /** As in `Receipt`. */
  readonly json: Buffer;
  readonly signature: Buffer;
  readonly cellCert: Buffer;
  /**
   * Appended as final, or an interim last-will record nothing has superseded for 30 seconds
   * (its cell stopped flushing: `cell_lost`).
   */
  readonly final: boolean;
  /** When the log received it, Unix milliseconds. */
  readonly receivedUnixMs: number;
  /** Every record the log received for this sandbox, superseded ones included. */
  readonly records: number;
  /** How many of them were appended as final: exactly one for a sandbox that ended. */
  readonly finals: number;
  /** `json`, parsed. */
  readonly doc: JsonObject;
}

/** A sandbox's egress log from the customer's verifier, its `sha256` already checked over its lines. */
export interface EgressLog {
  readonly sandboxId: SandboxId;
  /** One JSON line per connection. */
  readonly lines: readonly string[];
  /** SHA-256 over every line followed by a newline, lowercase hex. */
  readonly sha256: string;
  /**
   * True when this is the log `receipt` committed to: the receipt is for this sandbox and its
   * `egress_log_hash` is `sha256`. A receipt without one (the sandbox had no egress) matches
   * only an empty log. Takes a `Receipt` or a `LoggedReceipt`.
   */
  matches(receipt: { readonly doc: JsonObject }): boolean;
}

/**
 * SHA-256 over every line followed by a newline (UTF-8), lowercase hex: how a cell hashes a
 * sandbox's egress log into its receipt's `egress_log_hash`.
 */
export function egressLogSha256(lines: Iterable<string>): string {
  const hash = createHash("sha256");
  for (const line of lines) hash.update(`${line}\n`, "utf8");
  return hash.digest("hex");
}

function isObject(value: Json | undefined): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseDoc(json: Buffer, source: string): JsonObject {
  let doc: unknown;
  try {
    doc = JSON.parse(json.toString("utf8"));
  } catch {
    throw protocolError(`${source} is not JSON`);
  }
  if (typeof doc !== "object" || doc === null || Array.isArray(doc)) throw protocolError(`${source} is not a JSON object`);
  // JSON.parse yields only JSON values, so an object it returned is a JSON object.
  return doc as JsonObject;
}

export function parseReceipt({ json, signature, exitKind, cellCert, final }: pb.Receipt): Receipt {
  const doc = parseDoc(json, "the cell's receipt");
  return { json, signature, cellCert, final, exitKind: pb.EXIT_KINDS[exitKind], doc, data: doc };
}

export function parseLoggedReceipt({ receipt, signature, cellCert, final, receivedUnixMs, records, finals }: pb.LoggedReceipt): LoggedReceipt {
  return { json: receipt, signature, cellCert, final, receivedUnixMs, records, finals, doc: parseDoc(receipt, "a logged receipt") };
}

/** Checks the verifier's egress log against its own hash; `EgressLogMismatch` if they differ. */
export function parseEgressLog(sandboxId: SandboxId, { lines, sha256 }: pb.GetEgressLogResponse): EgressLog {
  const actual = egressLogSha256(lines);
  if (actual !== sha256) {
    throw new EgressLogMismatch(
      `the egress log of sandbox ${sandboxId} hashes to ${actual}, not the ${JSON.stringify(sha256)} the verifier sent with it`,
      { code: grpc.status.DATA_LOSS },
    );
  }
  return {
    sandboxId,
    lines,
    sha256: actual,
    matches({ doc }) {
      const sandbox = doc["sandbox"];
      if (!isObject(sandbox) || sandbox["id"] !== sandboxId) return false;
      const committed = doc["egress_log_hash"];
      return committed === undefined || committed === null ? lines.length === 0 : committed === actual;
    },
  };
}
