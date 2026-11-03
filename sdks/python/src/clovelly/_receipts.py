"""Receipts (SPEC.md "Receipt"): what a cell signs for each sandbox, and the customer's
receipt log at their own verifier.

The SDK exposes the pieces a receipt is checked with (the canonical JSON that was signed,
the signature and the cell certificate) but does not verify them itself: the public
receipt tool does, from the receipt, the certificate chain to the environment CA and the
published measurement set.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Iterable, Union

from clovelly.cell.v1 import cell_pb2
from clovelly.verifier.v1 import verifier_pb2

from .errors import EgressLogMismatch, ProtocolError

__all__ = ["Receipt", "LoggedReceipt", "EgressLog", "exit_kind_name", "egress_log_sha256"]


def exit_kind_name(value: int) -> str:
    """``EXIT_KIND_REVOKED`` -> ``"revoked"``; a kind this SDK does not know keeps its number."""
    try:
        name = cell_pb2.ExitKind.Name(value)
    except ValueError:
        return f"unknown_{value}"
    return name[len("EXIT_KIND_"):].lower()


def _doc(raw: bytes, source: str) -> dict[str, Any]:
    try:
        doc = json.loads(raw)
    except ValueError as err:
        raise ProtocolError(f"{source} is not JSON: {err}") from None
    if not isinstance(doc, dict):
        raise ProtocolError(f"{source} is not a JSON object")
    return doc


@dataclass(frozen=True)
class Receipt:
    """A sandbox's signed receipt as its cell returned it (``Sandbox.close``,
    ``Sandbox.receipt``, ``Cell.kill``, ``Cell.get_receipt``).

    ``json`` is the receipt in JCS canonical form: exactly the bytes ``signature`` (ECDSA
    P-256 with SHA-256, ``r || s``) covers, under the key of ``cell_cert`` (DER), which
    chains to the environment CA. ``final`` is set once the sandbox has ended and no later
    receipt will follow. ``exit_kind`` is the lowercase kind (``"running"`` while it runs,
    ``"killed"``, ``"exited"``, ...) and ``doc`` the parsed JSON.
    """

    json: bytes = field(repr=False)
    signature: bytes = field(repr=False)
    cell_cert: bytes = field(repr=False)
    final: bool
    exit_kind: str
    doc: dict[str, Any]

    @property
    def data(self) -> dict[str, Any]:
        """``doc``, under the name phases 2 and 3 gave it."""
        return self.doc

    @classmethod
    def _from_proto(cls, msg: cell_pb2.Receipt) -> Receipt:
        return cls(
            json=msg.json,
            signature=msg.signature,
            cell_cert=msg.cell_cert,
            final=msg.final,
            exit_kind=exit_kind_name(msg.exit_kind),
            doc=_doc(msg.json, "the cell's receipt"),
        )


@dataclass(frozen=True)
class LoggedReceipt:
    """One sandbox's record in the customer's receipt log (``Environment.receipts``): the
    latest receipt the log received for it.

    ``json``, ``signature`` and ``cell_cert`` are as in :class:`Receipt`. ``final`` is set
    when the record was appended as final, or is an interim last-will record nothing has
    superseded for 30 seconds (its cell stopped flushing: ``cell_lost``).
    ``received_unix_ms`` is when the log received it; ``records`` counts every record the
    log received for this sandbox, superseded ones included, and ``finals`` how many of
    them were appended as final (exactly one for a sandbox that ended).
    """

    json: bytes = field(repr=False)
    signature: bytes = field(repr=False)
    cell_cert: bytes = field(repr=False)
    final: bool
    received_unix_ms: int
    records: int
    finals: int
    doc: dict[str, Any]

    @classmethod
    def _from_proto(cls, msg: verifier_pb2.LoggedReceipt) -> LoggedReceipt:
        return cls(
            json=msg.receipt,
            signature=msg.signature,
            cell_cert=msg.cell_cert,
            final=msg.final,
            received_unix_ms=msg.received_unix_ms,
            records=msg.records,
            finals=msg.finals,
            doc=_doc(msg.receipt, "a logged receipt"),
        )


def egress_log_sha256(lines: Iterable[str]) -> str:
    """SHA-256 over every line followed by a newline (UTF-8), lowercase hex: how a cell
    hashes a sandbox's egress log into its receipt's ``egress_log_hash``."""
    hasher = hashlib.sha256()
    for line in lines:
        hasher.update(line.encode("utf-8"))
        hasher.update(b"\n")
    return hasher.hexdigest()


@dataclass(frozen=True)
class EgressLog:
    """A sandbox's egress log from the customer's verifier (``Environment.egress_log``):
    one JSON line per connection, and ``sha256`` over them, which the SDK has checked."""

    sandbox_id: str
    lines: tuple[str, ...]
    sha256: str

    def matches(self, receipt: Union[Receipt, LoggedReceipt]) -> bool:
        """True when this is the log ``receipt`` committed to: the receipt is for this
        sandbox and its ``egress_log_hash`` is ``sha256``. A receipt without one (the
        sandbox had no egress) matches only an empty log."""
        sandbox = receipt.doc.get("sandbox")
        if not isinstance(sandbox, dict) or sandbox.get("id") != self.sandbox_id:
            return False
        committed = receipt.doc.get("egress_log_hash")
        if committed is None:
            return not self.lines
        return committed == self.sha256

    @classmethod
    def _from_proto(cls, sandbox_id: str, msg: verifier_pb2.GetEgressLogResponse) -> EgressLog:
        lines = tuple(msg.lines)
        actual = egress_log_sha256(lines)
        if actual != msg.sha256:
            raise EgressLogMismatch(
                f"the egress log of sandbox {sandbox_id} hashes to {actual}, "
                f"not the {msg.sha256!r} the verifier sent with it"
            )
        return cls(sandbox_id=sandbox_id, lines=lines, sha256=actual)
