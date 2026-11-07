"""Typed errors.

Every refusal from a cell or the control plane ends with a gRPC status whose trailing
metadata key ``clovelly-error`` holds one ``ErrorReason`` name (proto/clovelly/cell/v1/cell.proto
and proto/clovelly/control/v1/control.proto). The SDK raises one subclass of
:class:`ClovellyError` per reason, so callers can ``except CapacityError:`` rather than parse
messages. A reason the SDK does not know (a newer server) raises a plain ``ClovellyError``
with ``.reason`` still set.

Transport failures have their own types: :class:`CellVerificationError` when a cell's
TLS certificate is refused (nothing was sent to it), :class:`CellUnavailable` when a
verified cell cannot be reached, :class:`ControlPlaneUnavailable` for the control plane.
"""

from __future__ import annotations

from typing import Literal, Mapping, Optional, Type

import grpc

__all__ = [
    "ClovellyError",
    "InvalidSandboxId",
    "InvalidRequest",
    "SandboxNotFound",
    "PermissionDenied",
    "SandboxExists",
    "CapacityError",
    "AbovePolicyMaximum",
    "CrossesCellEnd",
    "CrossesReleaseExpiry",
    "CellDraining",
    "CellRevoked",
    "SandboxEnded",
    "FileNotFound",
    "RuntimeFailure",
    "PolicyRefused",
    "CredentialUnavailable",
    "StorageUnavailable",
    "TemplateUnavailable",
    "VolumeBusy",
    "VolumeUnreadable",
    "VolumeUnavailable",
    "NoSuchTemplate",
    "VerifierUnavailable",
    "Unauthenticated",
    "NoSuchEnvironment",
    "NoSuchSubenvironment",
    "NoSuchPool",
    "NoSuchCell",
    "NoCellCanHold",
    "NoCellReady",
    "CellCreateFailed",
    "QuotaExceeded",
    "CreditExhausted",
    "NoCapacity",
    "UnknownRegion",
    "CellVerificationError",
    "CellUnavailable",
    "ControlPlaneUnavailable",
    "ProtocolError",
    "EgressLogMismatch",
    "VerificationKind",
]


class ClovellyError(Exception):
    """Base class of every error the SDK raises for a refused or failed call.

    ``reason`` is the ``clovelly-error`` trailer (an ``ErrorReason`` name such as
    ``"CAPACITY"``) or None when the server sent none; ``code`` is the gRPC status code
    name (such as ``"RESOURCE_EXHAUSTED"``) or None when no RPC failed; ``details`` is
    the server's or the SDK's message, for people.
    """

    def __init__(
        self, details: str, *, reason: Optional[str] = None, code: Optional[str] = None
    ) -> None:
        super().__init__(details)
        self.details = details
        self.reason = reason
        self.code = code

    def __str__(self) -> str:
        tags = ", ".join(dict.fromkeys(tag for tag in (self.code, self.reason) if tag))
        return f"{self.details} [{tags}]" if tags else self.details


# Reasons from either service. The same name means the same thing in both protos.


class InvalidRequest(ClovellyError):
    """INVALID_REQUEST: a malformed request (zero size, empty argv, missing header)."""


class PermissionDenied(ClovellyError):
    """PERMISSION: the cell refused the sandbox's access key, or the control-plane token
    may not make this call."""


class SandboxNotFound(ClovellyError):
    """NO_SUCH_SANDBOX: the cell (or the control plane) has no sandbox with this id."""


class AbovePolicyMaximum(ClovellyError):
    """ABOVE_POLICY_MAXIMUM: cpu, memory or timeout is above the sub-environment's
    maximum. Raised by the control plane before placing, or by the cell from its signed
    policy bundle."""


class VolumeBusy(ClovellyError):
    """VOLUME_BUSY: another sandbox holds the volume's single-mounter lease. Raised by
    the cell at create, or by the control plane."""


# Cell reasons.


class InvalidSandboxId(ClovellyError):
    """INVALID_SANDBOX_ID: the sandbox id is not 32 lowercase hex characters."""


class SandboxExists(ClovellyError):
    """SANDBOX_EXISTS: a sandbox with this id already exists on the cell."""


class CapacityError(ClovellyError):
    """CAPACITY: the request does not fit the cell's unreserved CPU or memory. The SDK
    places the sandbox on another cell before raising this."""


class CrossesCellEnd(ClovellyError):
    """CROSSES_CELL_END: now + timeout is after the cell's cap. Re-placed by the SDK."""


class CrossesReleaseExpiry(ClovellyError):
    """CROSSES_RELEASE_EXPIRY: now + timeout reaches the release's valid_until.
    Re-placed by the SDK."""


class CellDraining(ClovellyError):
    """DRAINING: the cell is draining or recycling. Re-placed by the SDK."""


class CellRevoked(ClovellyError):
    """REVOKED: the cell's key lease ended and it has ended every sandbox."""


class SandboxEnded(ClovellyError):
    """SANDBOX_ENDED: the sandbox has ended; its receipt is still available."""


class FileNotFound(ClovellyError):
    """NO_SUCH_FILE: ReadFile on a path that does not exist or is not readable."""


class RuntimeFailure(ClovellyError):
    """RUNTIME: runsc failed inside the cell."""


# Control-plane reasons.


class Unauthenticated(ClovellyError):
    """UNAUTHENTICATED: the control plane refused the API token."""


class NoSuchEnvironment(ClovellyError):
    """NO_SUCH_ENVIRONMENT."""


class NoSuchSubenvironment(ClovellyError):
    """NO_SUCH_SUBENVIRONMENT."""


class NoSuchPool(ClovellyError):
    """NO_SUCH_POOL: the sub-environment has no pool."""


class NoSuchCell(ClovellyError):
    """NO_SUCH_CELL."""


class NoCellCanHold(ClovellyError):
    """NO_CELL_CAN_HOLD: no cell of the pool could ever hold the request (larger than a
    cell, or a timeout past a fresh cell's cap or its release's valid_until)."""


class NoCellReady(ClovellyError):
    """NO_CELL_READY: a cell was booted but none became ready before the deadline."""


class CellCreateFailed(ClovellyError):
    """CELL_CREATE_FAILED: the Compute API refused to create a cell."""


class QuotaExceeded(ClovellyError):
    """QUOTA_EXCEEDED: the environment is at a quota (cells, sandboxes or volume bytes).
    Refused at once, never queued; the message names the quota."""


class NoCapacity(ClovellyError):
    """NO_CAPACITY: every zone of the pool's region is out of machines and no cell of the
    pool can take the sandbox. Nothing was billed and nothing is queued; no other region is
    tried. ``region`` names the region; ``retry_after`` is how many seconds until the
    control plane tries those zones again (docs/regions.md). Create the sandbox in a
    sub-environment of another region, or retry after that."""

    def __init__(
        self,
        details: str,
        *,
        region: str,
        retry_after: int,
        reason: Optional[str] = None,
        code: Optional[str] = None,
    ) -> None:
        super().__init__(details, reason=reason, code=code)
        self.region = region
        self.retry_after = retry_after


class UnknownRegion(ClovellyError):
    """UNKNOWN_REGION: the region is not in the published list; ``regions`` is the list."""

    def __init__(
        self,
        details: str,
        *,
        regions: tuple[str, ...],
        reason: Optional[str] = None,
        code: Optional[str] = None,
    ) -> None:
        super().__init__(details, reason=reason, code=code)
        self.regions = regions


class CreditExhausted(ClovellyError):
    """CREDIT_EXHAUSTED: the organization has no credit, no card on file, or a failed charge
    past its grace, so nothing new is placed. Running sandboxes finish to their timeout; credit
    added resumes placements within a minute. The message says which (docs/billing.md)."""


# Transport.

VerificationKind = Literal["untrusted_certificate", "name_mismatch", "handshake"]


class CellVerificationError(ClovellyError):
    """The cell's TLS handshake failed, so nothing beyond the handshake reached it.

    ``kind`` says why: ``"untrusted_certificate"`` (self-signed, or issued by a CA other
    than this environment's), ``"name_mismatch"`` (the certificate does not name this
    environment and sub-environment) or ``"handshake"`` (any other TLS failure, such as
    a server that does not speak TLS). ``address`` is the cell address that was dialled.
    """

    def __init__(
        self, details: str, *, kind: VerificationKind, address: str, code: Optional[str] = None
    ) -> None:
        super().__init__(details, code=code)
        self.kind: VerificationKind = kind
        self.address = address


class CellUnavailable(ClovellyError):
    """A cell could not be reached, or did not answer in time, over a connection whose
    certificate was not refused (UNAVAILABLE or DEADLINE_EXCEEDED with no reason)."""


class PolicyRefused(ClovellyError):
    """POLICY_REFUSED: the cell holds no policy bundle it can accept for the
    sub-environment (bad signature, wrong environment, expired, older than the one in
    force, or an invalid destination), so it creates no sandbox until the verifier
    serves one it can."""


class CredentialUnavailable(ClovellyError):
    """CREDENTIAL_UNAVAILABLE: a credential the policy names could not be fetched or
    did not open under the sub-environment DEK."""


class StorageUnavailable(ClovellyError):
    """STORAGE: the control plane could not store or read ciphertext."""


class TemplateUnavailable(ClovellyError):
    """TEMPLATE_UNAVAILABLE: the cell could not fetch the template, it did not open under
    the sub-environment DEK, or its plaintext does not have the digest asked for."""


class VolumeUnreadable(ClovellyError):
    """VOLUME_UNREADABLE: the volume's key does not open under this sub-environment's DEK
    (it belongs to another sub-environment or environment), or its blocks fail their
    authenticated manifest."""


class VolumeUnavailable(ClovellyError):
    """VOLUME_UNAVAILABLE: the cell could not reach the volume's lease or blocks."""


class NoSuchTemplate(ClovellyError):
    """NO_SUCH_TEMPLATE: the sub-environment has no template of that name."""


class ControlPlaneUnavailable(ClovellyError):
    """The control plane could not be reached or did not answer in time."""


class VerifierUnavailable(ClovellyError):
    """The customer's verifier could not be reached or did not answer (a missing or
    wrong SDK token is ``Unauthenticated``)."""


class ProtocolError(ClovellyError):
    """A server broke the protocol: a malformed placement, an Exec stream with no exit,
    a receipt that is not JSON."""


class EgressLogMismatch(ProtocolError):
    """The egress log the verifier returned does not hash to the SHA-256 it returned
    with it, so the lines cannot be trusted to be the ones the receipt committed to."""


_ErrorTable = Mapping[str, Type[ClovellyError]]

_CELL_REASONS: _ErrorTable = {
    "INVALID_SANDBOX_ID": InvalidSandboxId,
    "INVALID_REQUEST": InvalidRequest,
    "NO_SUCH_SANDBOX": SandboxNotFound,
    "PERMISSION": PermissionDenied,
    "SANDBOX_EXISTS": SandboxExists,
    "CAPACITY": CapacityError,
    "ABOVE_POLICY_MAXIMUM": AbovePolicyMaximum,
    "CROSSES_CELL_END": CrossesCellEnd,
    "CROSSES_RELEASE_EXPIRY": CrossesReleaseExpiry,
    "DRAINING": CellDraining,
    "REVOKED": CellRevoked,
    "SANDBOX_ENDED": SandboxEnded,
    "NO_SUCH_FILE": FileNotFound,
    "RUNTIME": RuntimeFailure,
    "POLICY_REFUSED": PolicyRefused,
    "CREDENTIAL_UNAVAILABLE": CredentialUnavailable,
    "TEMPLATE_UNAVAILABLE": TemplateUnavailable,
    "VOLUME_BUSY": VolumeBusy,
    "VOLUME_UNREADABLE": VolumeUnreadable,
    "VOLUME_UNAVAILABLE": VolumeUnavailable,
}

_CONTROL_REASONS: _ErrorTable = {
    "UNAUTHENTICATED": Unauthenticated,
    "PERMISSION": PermissionDenied,
    "INVALID_REQUEST": InvalidRequest,
    "NO_SUCH_ENVIRONMENT": NoSuchEnvironment,
    "NO_SUCH_SUBENVIRONMENT": NoSuchSubenvironment,
    "NO_SUCH_POOL": NoSuchPool,
    "NO_SUCH_SANDBOX": SandboxNotFound,
    "NO_SUCH_CELL": NoSuchCell,
    "ABOVE_POLICY_MAXIMUM": AbovePolicyMaximum,
    "NO_CELL_CAN_HOLD": NoCellCanHold,
    "NO_CELL_READY": NoCellReady,
    "CELL_CREATE_FAILED": CellCreateFailed,
    "STORAGE": StorageUnavailable,
    "NO_SUCH_TEMPLATE": NoSuchTemplate,
    "VOLUME_BUSY": VolumeBusy,
    "QUOTA_EXCEEDED": QuotaExceeded,
    "CREDIT_EXHAUSTED": CreditExhausted,
    "NOT_READY": ControlPlaneUnavailable,
    "SIGN_UP_CLOSED": PermissionDenied,
    # Built with their trailers by _from_rpc.
    "NO_CAPACITY": NoCapacity,
    "UNKNOWN_REGION": UnknownRegion,
}

_TRANSPORT_CODES = (grpc.StatusCode.UNAVAILABLE, grpc.StatusCode.DEADLINE_EXCEEDED)


def _trailer(err: grpc.RpcError, name: str) -> Optional[str]:
    """One trailing metadata value of a failed call, if the server sent it."""
    for key, value in err.trailing_metadata() or ():
        if key == name:
            return value if isinstance(value, str) else value.decode("ascii", "replace")
    return None


def _reason(err: grpc.RpcError) -> Optional[str]:
    """The ``clovelly-error`` trailer of a failed call, if the server sent one."""
    return _trailer(err, "clovelly-error")


def _seconds(value: Optional[str]) -> int:
    try:
        return max(0, int(value or ""))
    except ValueError:
        return 0


def _from_rpc(
    err: grpc.RpcError, table: _ErrorTable, unavailable: Type[ClovellyError]
) -> ClovellyError:
    code = err.code()
    details = err.details() or ""
    reason = _reason(err)
    if table.get(reason or "") is NoCapacity:
        return NoCapacity(
            details,
            region=_trailer(err, "clovelly-region") or "",
            retry_after=_seconds(_trailer(err, "clovelly-retry-after")),
            reason=reason,
            code=code.name,
        )
    if table.get(reason or "") is UnknownRegion:
        listed = _trailer(err, "clovelly-regions") or ""
        regions = tuple(r for r in listed.split(",") if r)
        return UnknownRegion(details, regions=regions, reason=reason, code=code.name)
    if reason is not None:
        return table.get(reason, ClovellyError)(details, reason=reason, code=code.name)
    if code in _TRANSPORT_CODES:
        return unavailable(details, code=code.name)
    return ClovellyError(details, code=code.name)


def _cell_error(err: grpc.RpcError) -> ClovellyError:
    """Maps a failed cell call to its typed error. Handshake failures are classified by
    the caller first (see ``_cell.handshake_kind``)."""
    return _from_rpc(err, _CELL_REASONS, CellUnavailable)


def _control_error(err: grpc.RpcError) -> ClovellyError:
    """Maps a failed control-plane call to its typed error."""
    return _from_rpc(err, _CONTROL_REASONS, ControlPlaneUnavailable)


def _verifier_error(
    err: grpc.RpcError, not_found: Type[ClovellyError] = NoSuchSubenvironment
) -> ClovellyError:
    """Maps a failed verifier call, which carries no trailer. ``not_found`` is what
    NOT_FOUND means for this call: the sub-environment for sealing and listing, the
    sandbox for ``GetEgressLog``."""
    code = err.code()
    details = err.details() or ""
    if code == grpc.StatusCode.UNAUTHENTICATED:
        return Unauthenticated(details, code=code.name)
    if code == grpc.StatusCode.INVALID_ARGUMENT:
        return InvalidRequest(details, code=code.name)
    if code == grpc.StatusCode.NOT_FOUND:
        return not_found(details, code=code.name)
    return VerifierUnavailable(details, code=code.name)
