"""One verified TLS connection to one cell, and the raw cell API over it.

Connection rules (SPEC.md "The SDK", decision 2), not configurable off:

- The cell is dialled at its region's relay address (``ipv4:<host:port>``) with TLS
  server name and HTTP/2 authority set to the cell's own name,
  ``<instance>.<zone>.<subenv>.<env>.cells.clovelly.internal``, from the placement. The
  relay routes the connection by that name and terminates nothing.
- The only trust anchor is the environment CA. gRPC's standard verification checks
  the chain against it and the certificate's SAN against that name; there are no
  custom certificate callbacks. The CA pins the environment; the name, which the SDK
  checks is under the expected sub-environment before dialling, pins the
  sub-environment and the cell.
- Before any call that carries data, the connection is probed with an empty
  ``grpc.health.v1.Health/Check``. gRPC sends nothing until the handshake has verified
  the certificate, so a refused cell receives nothing beyond the TLS handshake. A
  refusal raises :class:`CellVerificationError` and closes the channel for good.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Iterator, Literal, Mapping, Optional, Sequence, TypeVar, Union

import grpc
from grpc_health.v1 import health_pb2, health_pb2_grpc

from clovelly.cell.v1 import cell_pb2, cell_pb2_grpc

from . import _parse
from ._receipts import Receipt, exit_kind_name
from .errors import (
    ClovellyError,
    CellUnavailable,
    CellVerificationError,
    ProtocolError,
    VerificationKind,
    _cell_error,
)

__all__ = ["Cell", "ExecResult"]

PROBE_TIMEOUT_SECS = 15.0
# How long a cell nobody can reach yet is waited for. Through the relay a placed cell answers
# at once (phase 12); the wait covers a relay instance being replaced, and a control plane
# from before the relay, whose per-cell forwarding rules answered a client tens of seconds
# after the control plane (phase 2: still unreachable 27 s after it was placed on).
CONNECT_WAIT_SECS = 90.0
# The longest wait between reconnects of a cell's connection.
RECONNECT_BACKOFF_MS = 2000
# Between probes when the cell could not be reached at all.
CONNECT_RETRY_SECS = 2.0
# Deadline for unary cell calls (CreateSandbox includes runsc create and start).
CALL_TIMEOUT_SECS = 60.0
# An exec with a timeout gets this long past it for the cell to report the kill.
EXEC_GRACE_SECS = 30.0
CHUNK_BYTES = 64 * 1024

_T = TypeVar("_T")


def handshake_kind(details: str) -> Optional[VerificationKind]:
    """Classifies a failed call's details as a TLS handshake refusal, or None if the
    failure happened elsewhere (connection refused, timeout, a server status).

    The strings are gRPC core's (BoringSSL under grpcio): "Peer name <name> is not in
    peer certificate" for a SAN mismatch, "Ssl handshake failed ...
    CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate" for a chain that
    does not reach the environment CA.
    """
    text = details.lower()
    # gRPC core's TCP connect stage ("tcp handshaker shutdown", a refused or timed-out
    # connect) is not TLS: the cell could not be reached.
    if any(m in text for m in ("tcp handshaker", "failed to connect to remote host", "connection refused")):
        return None
    if "is not in peer certificate" in text or "peer name" in text:
        return "name_mismatch"
    if any(
        marker in text
        for marker in (
            "certificate_verify_failed",
            "certificate verify failed",
            "unable to get local issuer",
            "self signed",
            "self-signed",
        )
    ):
        return "untrusted_certificate"
    if any(marker in text for marker in ("handshake", "ssl_error", "tsi_", "peer certificate")):
        return "handshake"
    return None


@dataclass(frozen=True)
class ExecResult:
    """What ``Sandbox.exec`` returns once the process has exited.

    ``first_exec_ms`` is set on the sandbox's first exec only: the cell's measure from
    ``runsc create`` to this exec's first stdout byte. ``first_stdout_at`` is the
    ``time.perf_counter()`` when the first stdout chunk arrived here, for latency
    measured from the SDK. ``sandbox_ended`` names the exit kind (e.g. ``"revoked"``)
    when the sandbox itself ended while the exec ran.
    """

    exit_code: int
    stdout: bytes
    stderr: bytes
    first_exec_ms: Optional[int]
    first_stdout_at: Optional[float]
    sandbox_ended: Optional[str]


# A cell connection is unverified until its probe succeeds, verified after, and closed
# for good on a refusal or close(); a closed one holds the error later calls raise.
_State = Union[Literal["unverified", "verified"], ClovellyError]


class Cell:
    """A TLS connection to one cell, shared by every sandbox on it (gRPC multiplexes
    their streams). Thread-safe.

    Get one from ``Environment.cell(address, name)``; ``Environment.sandbox`` uses the
    same objects. Every method other than :meth:`verify` runs the verification probe
    first if it has not passed yet. The RPC methods mirror the cell API one to one and
    pass ids and keys through unchecked, so tests can exercise the cell's own checks;
    they raise the typed errors in :mod:`clovelly.errors`.
    """

    def __init__(self, address: _parse.CellAddress, name: _parse.CellName, ca: bytes) -> None:
        self.address = address
        self.name = name
        self.subenv = _parse.subenv_of(name)
        self._lock = threading.RLock()
        self._state: _State = "unverified"
        self._channel = grpc.secure_channel(
            f"ipv4:{address}",
            grpc.ssl_channel_credentials(root_certificates=ca),
            options=[
                ("grpc.ssl_target_name_override", self.name),
                ("grpc.default_authority", self.name),
                # This channel owns its connection: closing it after a refusal drops
                # the connection, and no other channel's connection is reused.
                ("grpc.use_local_subchannel_pool", 1),
                # Reconnect within 2 s, not gRPC's growing backoff: when one of a region's
                # relay instances goes, the next connection lands on another (phase 12).
                ("grpc.max_reconnect_backoff_ms", RECONNECT_BACKOFF_MS),
            ],
        )
        self._health = health_pb2_grpc.HealthStub(self._channel)
        self._stub = cell_pb2_grpc.CellStub(self._channel)

    def __repr__(self) -> str:
        return f"Cell({self.address!r}, name={self.name!r}, state={self.state!r})"

    @property
    def state(self) -> str:
        """``"unverified"``, ``"verified"`` or ``"closed"``."""
        state = self._state
        return "closed" if isinstance(state, ClovellyError) else state

    @property
    def verified(self) -> bool:
        return self._state == "verified"

    @property
    def closed(self) -> bool:
        return isinstance(self._state, ClovellyError)

    def verify(self) -> None:
        """Probes the connection with an empty Health/Check, which can only succeed once
        the TLS handshake has verified the cell's certificate against the environment
        CA and this sub-environment's name.

        Raises :class:`CellVerificationError` (and closes the connection for good) when
        the handshake fails, :class:`CellUnavailable` when the cell cannot be reached.
        Returns immediately when already verified. A probe that times out (the cell is
        slow to accept the connection) or that cannot connect yet is retried, up to five
        probes in all.
        """
        with self._lock:
            state = self._state
            if isinstance(state, ClovellyError):
                raise state.with_traceback(None)
            if state == "verified":
                return
            self._probe()
            self._state = "verified"

    def _probe(self) -> None:
        give_up = time.monotonic() + CONNECT_WAIT_SECS
        while True:
            try:
                self._health.Check(
                    health_pb2.HealthCheckRequest(),
                    timeout=PROBE_TIMEOUT_SECS,
                    wait_for_ready=False,
                )
                return
            except grpc.RpcError as err:
                # A fail-fast call only times out while the channel is still connecting
                # (a failed connect or handshake is UNAVAILABLE at once) or when a
                # connected cell does not answer. Retrying is harmless either way; the
                # connectivity state is not consulted because grpc's subscribe() poller
                # races with channel.close().
                if err.code() is grpc.StatusCode.DEADLINE_EXCEEDED and time.monotonic() < give_up:
                    continue
                # A cell that could not be reached at all (no TLS yet) may be moments
                # from routing its address; the channel reconnects with backoff. A TLS
                # refusal is final at once.
                if (
                    err.code() is grpc.StatusCode.UNAVAILABLE
                    and handshake_kind(err.details() or "") is None
                    and time.monotonic() < give_up
                ):
                    time.sleep(CONNECT_RETRY_SECS)
                    continue
                raise self._failure(err) from None

    def create_sandbox(
        self,
        sandbox_id: str,
        key: bytes,
        cpu_halves: int,
        memory_gib: int,
        timeout_secs: int,
        command: Sequence[str] = (),
        env: Optional[Mapping[str, str]] = None,
        *,
        template_digest: str = "",
        volume: str = "",
        volume_gib: int = 0,
        placement_pass: str = "",
    ) -> cell_pb2.CreateSandboxResponse:
        """``Cell.CreateSandbox``: returns the response (``started_unix_ms``, ``runsc_ms``).
        Empty ``template_digest`` and ``volume`` mean the base bundle and no volume.
        ``placement_pass`` is the placement's pass, which a cell with a control plane requires."""
        request = cell_pb2.CreateSandboxRequest(
            sandbox_id=sandbox_id,
            access_key=key,
            cpu_halves=cpu_halves,
            memory_gib=memory_gib,
            timeout_secs=timeout_secs,
            command=list(command),
            env=dict(env or {}),
            template_digest=template_digest,
            volume=volume,
            volume_gib=volume_gib,
            placement_pass=placement_pass,
        )
        return self._call(lambda: self._stub.CreateSandbox(request, timeout=CALL_TIMEOUT_SECS))

    def exec(
        self,
        sandbox_id: str,
        key: bytes,
        args: Sequence[str],
        *,
        stdin: bytes = b"",
        env: Optional[Mapping[str, str]] = None,
        cwd: str = "",
        timeout_secs: int = 0,
    ) -> ExecResult:
        """``Cell.Exec``: sends ExecStart, ``stdin`` in 64 KiB chunks and stdin_eof, then
        collects stdout and stderr until ExecExit."""
        start = cell_pb2.ExecStart(
            sandbox_id=sandbox_id,
            access_key=key,
            args=list(args),
            env=dict(env or {}),
            cwd=cwd,
            timeout_secs=timeout_secs,
        )

        def requests() -> Iterator[cell_pb2.ExecRequest]:
            yield cell_pb2.ExecRequest(start=start)
            for offset in range(0, len(stdin), CHUNK_BYTES):
                yield cell_pb2.ExecRequest(stdin=stdin[offset : offset + CHUNK_BYTES])
            yield cell_pb2.ExecRequest(stdin_eof=True)

        deadline = timeout_secs + EXEC_GRACE_SECS if timeout_secs else None

        def run() -> ExecResult:
            stdout, stderr = bytearray(), bytearray()
            first_stdout_at: Optional[float] = None
            exit_msg: Optional[cell_pb2.ExecExit] = None
            for response in self._stub.Exec(requests(), timeout=deadline):
                which = response.WhichOneof("msg")
                if which == "stdout":
                    if first_stdout_at is None:
                        first_stdout_at = time.perf_counter()
                    stdout += response.stdout
                elif which == "stderr":
                    stderr += response.stderr
                elif which == "exit":
                    exit_msg = response.exit
            if exit_msg is None:
                raise ProtocolError("the cell ended an Exec stream without ExecExit")
            return ExecResult(
                exit_code=exit_msg.code,
                stdout=bytes(stdout),
                stderr=bytes(stderr),
                first_exec_ms=exit_msg.first_exec_ms or None,
                first_stdout_at=first_stdout_at,
                sandbox_ended=exit_kind_name(exit_msg.sandbox_ended) if exit_msg.sandbox_ended else None,
            )

        return self._call(run)

    def read_file(self, sandbox_id: str, key: bytes, path: str) -> bytes:
        """``Cell.ReadFile``: the whole file."""
        request = cell_pb2.ReadFileRequest(sandbox_id=sandbox_id, access_key=key, path=path)
        return self._call(lambda: b"".join(chunk.data for chunk in self._stub.ReadFile(request)))

    def write_file(self, sandbox_id: str, key: bytes, path: str, data: bytes) -> int:
        """``Cell.WriteFile``: the header, then ``data`` in 64 KiB chunks; returns the
        bytes the cell wrote."""
        header = cell_pb2.WriteFileHeader(sandbox_id=sandbox_id, access_key=key, path=path)

        def requests() -> Iterator[cell_pb2.WriteFileRequest]:
            yield cell_pb2.WriteFileRequest(header=header)
            for offset in range(0, len(data), CHUNK_BYTES):
                yield cell_pb2.WriteFileRequest(data=data[offset : offset + CHUNK_BYTES])

        return self._call(lambda: self._stub.WriteFile(requests()).bytes_written)

    def kill(self, sandbox_id: str, key: bytes) -> Receipt:
        """``Cell.Kill``: ends the sandbox (exit kind ``killed``) and returns its final receipt."""
        request = cell_pb2.KillRequest(sandbox_id=sandbox_id, access_key=key)
        return Receipt._from_proto(self._call(lambda: self._stub.Kill(request, timeout=CALL_TIMEOUT_SECS)))

    def get_receipt(self, sandbox_id: str, key: bytes) -> Receipt:
        """``Cell.GetReceipt``: interim while the sandbox runs, final once it has ended."""
        request = cell_pb2.GetReceiptRequest(sandbox_id=sandbox_id, access_key=key)
        return Receipt._from_proto(
            self._call(lambda: self._stub.GetReceipt(request, timeout=CALL_TIMEOUT_SECS))
        )

    def close(self) -> None:
        """Closes the connection. Calls in flight fail; later calls raise CellUnavailable."""
        self._close(CellUnavailable(f"the connection to cell {self.address} is closed"))

    def _call(self, rpc: Callable[[], _T]) -> _T:
        """Runs one data-carrying RPC, only on a verified connection."""
        if self._state != "verified":
            self.verify()
        try:
            return rpc()
        except grpc.RpcError as err:
            raise self._failure(err) from None

    def _failure(self, err: grpc.RpcError) -> ClovellyError:
        """The typed error for a failed call. A handshake refusal (the first one, or a
        reconnect that presents a bad certificate) closes the connection for good."""
        code = err.code()
        details = err.details() or ""
        if code is grpc.StatusCode.UNAVAILABLE:
            kind = handshake_kind(details)
            if kind is not None:
                refusal = CellVerificationError(
                    f"refused cell {self.name} at {self.address}: {details}",
                    kind=kind,
                    address=self.address,
                    code=code.name,
                )
                self._close(refusal)
                return refusal
        return _cell_error(err)

    def _close(self, reason: ClovellyError) -> None:
        with self._lock:
            if isinstance(self._state, ClovellyError):
                return
            self._state = reason
        self._channel.close()
