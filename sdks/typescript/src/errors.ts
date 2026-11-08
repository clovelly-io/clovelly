// Typed errors. A refused call ends with a gRPC status whose trailing metadata
// "clovelly-error" names an ErrorReason from cell.proto or control.proto; each reason has its
// own class, so callers catch what they can act on.
import * as grpc from "@grpc/grpc-js";

interface ClovellyErrorInit {
  code: grpc.status;
  reason?: string | undefined;
  details?: string;
  cause?: unknown;
}

/** Every error the SDK raises for a refused or failed call, local argument checks included. */
export class ClovellyError extends Error {
  /** The `clovelly-error` trailer, such as `"CAPACITY"`; undefined when the server sent none. */
  readonly reason: ErrorReason | (string & {}) | undefined;
  /** The gRPC status code. */
  readonly code: grpc.status;
  /** The status message, for people. */
  readonly details: string;

  constructor(message: string, { code, reason, details = message, cause }: ClovellyErrorInit) {
    super(message, { cause });
    this.name = new.target.name;
    this.code = code;
    this.reason = reason;
    this.details = details;
  }
}

/** INVALID_SANDBOX_ID: the sandbox id is not 32 lowercase hex characters. */
export class InvalidSandboxId extends ClovellyError {}
/** INVALID_REQUEST: a malformed request, from a server or the SDK's own argument checks. */
export class InvalidRequest extends ClovellyError {}
/** NO_SUCH_SANDBOX: no sandbox with this id (on this cell, or known to the control plane). */
export class SandboxNotFound extends ClovellyError {}
/** PERMISSION: the access key does not match the sandbox's, or the token is not allowed this call. */
export class PermissionDenied extends ClovellyError {}
/** SANDBOX_EXISTS: a sandbox with this id exists on the cell. */
export class SandboxExists extends ClovellyError {}
/** CAPACITY: the request does not fit the cell's unreserved CPU or memory. */
export class CapacityError extends ClovellyError {}
/** ABOVE_POLICY_MAXIMUM: cpu, memory or timeout above the sub-environment's maximum. */
export class AbovePolicyMaximum extends ClovellyError {}
/** CROSSES_CELL_END: the timeout would run past the cell's cap. */
export class CrossesCellEnd extends ClovellyError {}
/** CROSSES_RELEASE_EXPIRY: the timeout would run past the release's `valid_until`. */
export class CrossesReleaseExpiry extends ClovellyError {}
/** DRAINING: the cell is draining or recycling and takes no new sandboxes. */
export class CellDraining extends ClovellyError {}
/** REVOKED: the cell's key lease ended; it has ended every sandbox. */
export class CellRevoked extends ClovellyError {}
/** SANDBOX_ENDED: the sandbox has ended. */
export class SandboxEnded extends ClovellyError {}
/** NO_SUCH_FILE: ReadFile on a path that does not exist or is not readable. */
export class FileNotFound extends ClovellyError {}
/** RUNTIME: runsc failed. */
export class RuntimeFailure extends ClovellyError {}
/** POLICY_REFUSED: the cell holds no policy bundle it can accept; it creates no sandbox until it does. */
export class PolicyRefused extends ClovellyError {}
/** CREDENTIAL_UNAVAILABLE: a credential the policy names could not be fetched or opened. */
export class CredentialUnavailable extends ClovellyError {}
/**
 * TEMPLATE_UNAVAILABLE: the cell could not fetch the template, it did not open under the
 * sub-environment DEK, or its plaintext does not have the digest asked for.
 */
export class TemplateUnavailable extends ClovellyError {}
/** VOLUME_BUSY: another sandbox holds the volume's single-mounter lease (from a cell or the control plane). */
export class VolumeBusy extends ClovellyError {}
/**
 * VOLUME_UNREADABLE: the volume's key does not open under this sub-environment's DEK (it
 * belongs to another sub-environment or environment), or its blocks fail their manifest.
 */
export class VolumeUnreadable extends ClovellyError {}
/** VOLUME_UNAVAILABLE: the cell could not reach the volume's lease or blocks. */
export class VolumeUnavailable extends ClovellyError {}
/** STORAGE: the control plane could not store or read ciphertext. */
export class StorageUnavailable extends ClovellyError {}
/** NO_SUCH_TEMPLATE: the sub-environment has no template of that name. */
export class NoSuchTemplate extends ClovellyError {}
/** UNAUTHENTICATED: the control plane did not accept the API token, or the verifier the SDK token. */
export class Unauthenticated extends ClovellyError {}
/** NO_SUCH_ENVIRONMENT. */
export class NoSuchEnvironment extends ClovellyError {}
/** NO_SUCH_SUBENVIRONMENT. */
export class NoSuchSubenvironment extends ClovellyError {}
/** NO_SUCH_POOL: the sub-environment has no pool. */
export class NoSuchPool extends ClovellyError {}
/** NO_SUCH_CELL. */
export class NoSuchCell extends ClovellyError {}
/** NO_CELL_CAN_HOLD: no cell of the pool could ever hold the request. */
export class NoCellCanHold extends ClovellyError {}
/** NO_CELL_READY: a cell was booted but none became ready before the deadline. */
export class NoCellReady extends ClovellyError {}
/** The environment is at a quota (cells, sandboxes or volume bytes); never queued. */
export class QuotaExceeded extends ClovellyError {}
/**
 * CREDIT_EXHAUSTED: the organization has no credit, no card on file, or a failed charge past its
 * grace, so nothing new is placed. Running sandboxes finish to their timeout; credit added resumes
 * placements within a minute. The message says which, and what to do (docs/billing.md).
 */
export class CreditExhausted extends ClovellyError {}
/** CELL_CREATE_FAILED: the Compute API refused to create a cell. */
export class CellCreateFailed extends ClovellyError {}

/**
 * NO_CAPACITY: every zone of the pool's region is out of machines and no cell of the pool can
 * take the sandbox. Nothing was billed and nothing is queued; no other region is tried. Create
 * the sandbox in a sub-environment of another region, or retry after `retryAfter` seconds.
 */
export class NoCapacity extends ClovellyError {
  /** The region that is out, such as `"europe-west4"`. */
  readonly region: string;
  /** Seconds until the control plane tries the region's zones again. */
  readonly retryAfter: number;

  constructor(message: string, init: ClovellyErrorInit & { region?: string; retryAfter?: number }) {
    super(message, init);
    this.region = init.region ?? "";
    this.retryAfter = init.retryAfter ?? 0;
  }
}

/** UNKNOWN_REGION: the region is not in the published list; `regions` is the list. */
export class UnknownRegion extends ClovellyError {
  readonly regions: readonly string[];

  constructor(message: string, init: ClovellyErrorInit & { regions?: readonly string[] }) {
    super(message, init);
    this.regions = init.regions ?? [];
  }
}

/**
 * A server answered with something the protocol does not allow: a malformed placement
 * (bad cell address or sandbox id), a placement for another environment or sub-environment
 * than the one asked for, an Exec without an exit message, a receipt that is not JSON.
 */
export class ProtocolError extends ClovellyError {}

/**
 * The egress log the verifier returned does not hash to the SHA-256 it sent with it, so
 * its lines cannot be trusted to be the ones the receipt committed to.
 */
export class EgressLogMismatch extends ProtocolError {}

/** The cell could not be reached, or its health probe did not answer SERVING. */
export class CellUnavailable extends ClovellyError {}
/** The control plane could not be reached or did not answer in time. */
export class ControlPlaneUnavailable extends ClovellyError {}
/** The customer's verifier could not be reached or did not answer. */
export class VerifierUnavailable extends ClovellyError {}

/**
 * Why a cell was refused during the TLS handshake:
 * - `untrusted_certificate`: the certificate does not chain to the environment CA
 *   (self-signed, or issued by another CA), or is outside its validity period.
 * - `name_mismatch`: the certificate's SAN does not name this environment and sub-environment.
 * - `handshake`: any other TLS failure.
 */
export type CellVerificationKind = "untrusted_certificate" | "name_mismatch" | "handshake";

/**
 * The SDK refused a cell. Only the TLS handshake reached it: gRPC sends the first request
 * only after the handshake has verified the certificate.
 */
export class CellVerificationError extends ClovellyError {
  readonly kind: CellVerificationKind;
  /** The address dialled. */
  readonly address: string;
  /** The name the certificate had to carry: `<subenv>.<env>.cells.clovelly.internal`. */
  readonly serverName: string;

  constructor(kind: CellVerificationKind, address: string, serverName: string, cause: grpc.ServiceError) {
    super(`cell ${address} refused (${kind}): expected ${serverName} under the environment CA: ${cause.details}`, {
      code: cause.code,
      details: cause.details,
      cause,
    });
    this.kind = kind;
    this.address = address;
    this.serverName = serverName;
  }
}

/** A `ProtocolError` for an answer the SDK cannot accept. */
export function protocolError(message: string): ProtocolError {
  return new ProtocolError(message, { code: grpc.status.INTERNAL });
}

/** An `InvalidRequest` for the SDK's own argument checks, worded like the server's. */
export function invalidRequest(message: string): InvalidRequest {
  return new InvalidRequest(message, { code: grpc.status.INVALID_ARGUMENT, reason: "INVALID_REQUEST" });
}

/** One class per `clovelly-error` name. Names shared by both protos mean the same thing. */
const BY_REASON = {
  // cell.proto
  INVALID_SANDBOX_ID: InvalidSandboxId,
  INVALID_REQUEST: InvalidRequest,
  NO_SUCH_SANDBOX: SandboxNotFound,
  PERMISSION: PermissionDenied,
  SANDBOX_EXISTS: SandboxExists,
  CAPACITY: CapacityError,
  ABOVE_POLICY_MAXIMUM: AbovePolicyMaximum,
  CROSSES_CELL_END: CrossesCellEnd,
  CROSSES_RELEASE_EXPIRY: CrossesReleaseExpiry,
  DRAINING: CellDraining,
  REVOKED: CellRevoked,
  SANDBOX_ENDED: SandboxEnded,
  NO_SUCH_FILE: FileNotFound,
  RUNTIME: RuntimeFailure,
  POLICY_REFUSED: PolicyRefused,
  CREDENTIAL_UNAVAILABLE: CredentialUnavailable,
  TEMPLATE_UNAVAILABLE: TemplateUnavailable,
  VOLUME_BUSY: VolumeBusy,
  VOLUME_UNREADABLE: VolumeUnreadable,
  VOLUME_UNAVAILABLE: VolumeUnavailable,
  // control.proto (beyond the shared names above)
  UNAUTHENTICATED: Unauthenticated,
  NO_SUCH_ENVIRONMENT: NoSuchEnvironment,
  NO_SUCH_SUBENVIRONMENT: NoSuchSubenvironment,
  NO_SUCH_POOL: NoSuchPool,
  NO_SUCH_CELL: NoSuchCell,
  NO_CELL_CAN_HOLD: NoCellCanHold,
  NO_CELL_READY: NoCellReady,
  QUOTA_EXCEEDED: QuotaExceeded,
  CREDIT_EXHAUSTED: CreditExhausted,
  NOT_READY: ControlPlaneUnavailable,
  SIGN_UP_CLOSED: PermissionDenied,
  // Buying credit is the console's; an SDK sees it only as a bad request.
  BELOW_MINIMUM_TOP_UP: InvalidRequest,
  CELL_CREATE_FAILED: CellCreateFailed,
  STORAGE: StorageUnavailable,
  NO_SUCH_TEMPLATE: NoSuchTemplate,
} as const satisfies Record<string, typeof ClovellyError>;

/** The `clovelly-error` names of cell.proto and control.proto. */
export type ErrorReason = keyof typeof BY_REASON | WithTrailers;

/** Reasons whose errors carry more trailers than the reason; built by `clovellyError` itself. */
type WithTrailers = "NO_CAPACITY" | "UNKNOWN_REGION";

function isErrorReason(name: string): name is keyof typeof BY_REASON {
  return Object.hasOwn(BY_REASON, name);
}

/** True for the errors grpc-js reports for a failed call. */
export function isServiceError(error: unknown): error is grpc.ServiceError {
  return error instanceof Error && "code" in error && "details" in error && "metadata" in error;
}

/**
 * Turns a failed call into its typed error: the class for its `clovelly-error` reason, else
 * `unavailable` for an unreachable server or a deadline, else a plain `ClovellyError`.
 * Anything that is not a gRPC error is returned unchanged.
 */
export function clovellyError(
  error: unknown,
  unavailable: typeof CellUnavailable | typeof ControlPlaneUnavailable | typeof VerifierUnavailable,
): unknown {
  if (!isServiceError(error)) return error;
  const trailer = (name: string): string | undefined => error.metadata.get(name)[0]?.toString();
  const reason = trailer("clovelly-error");
  const message = `${reason ?? grpc.status[error.code]}: ${error.details}`;
  const init = { code: error.code, reason, details: error.details, cause: error };
  if (reason === "NO_CAPACITY") {
    const retryAfter = Number.parseInt(trailer("clovelly-retry-after") ?? "", 10);
    return new NoCapacity(message, { ...init, region: trailer("clovelly-region") ?? "", retryAfter: Number.isNaN(retryAfter) ? 0 : Math.max(0, retryAfter) });
  }
  if (reason === "UNKNOWN_REGION") {
    return new UnknownRegion(message, { ...init, regions: (trailer("clovelly-regions") ?? "").split(",").filter((r) => r !== "") });
  }
  if (reason !== undefined && isErrorReason(reason)) return new BY_REASON[reason](message, init);
  if (error.code === grpc.status.UNAVAILABLE || error.code === grpc.status.DEADLINE_EXCEEDED) {
    return new unavailable(message, init);
  }
  return new ClovellyError(message, init);
}

/**
 * A failed verifier call, which carries no `clovelly-error` trailer. `notFound` is what
 * NOT_FOUND means for the call: the sub-environment for sealing and listing, the sandbox
 * for `GetEgressLog`.
 */
export function verifierError(error: unknown, notFound: typeof ClovellyError = NoSuchSubenvironment): unknown {
  if (!isServiceError(error)) return error;
  const init = { code: error.code, details: error.details, cause: error };
  const message = `${grpc.status[error.code]}: ${error.details}`;
  switch (error.code) {
    case grpc.status.UNAUTHENTICATED:
      return new Unauthenticated(message, init);
    case grpc.status.INVALID_ARGUMENT:
      return new InvalidRequest(message, init);
    case grpc.status.NOT_FOUND:
      return new notFound(message, init);
    default:
      return new VerifierUnavailable(message, init);
  }
}
