"""The control plane's customer-facing calls: where to put a sandbox, where one lives,
that one was closed, and storing sealed credentials and encrypted templates.

The control plane is a service, not a trust input. It hands out placements (a cell
address and a sandbox id) and never sees content; whatever cell it names is verified
against the environment CA before anything is sent there. Every call carries
``authorization: Bearer <token>``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Iterator, Optional, Sequence

import grpc

from clovelly.control.v1 import control_pb2, control_pb2_grpc

from . import _parse
from ._template import Template
from .errors import ProtocolError, _control_error

__all__ = ["Control", "Placement", "Pool", "target"]

# A cold placement blocks while a cell boots (SPEC.md phase 2 criterion 6: within 3 minutes).
PLACE_TIMEOUT_SECS = 330.0
LOCATE_TIMEOUT_SECS = 30.0
RELEASE_TIMEOUT_SECS = 10.0
# A whole template upload: 2 GB at a few MB/s, with room to spare.
UPLOAD_TIMEOUT_SECS = 3600.0


def target(url: str) -> str:
    """``host:port`` or ``https://host:port`` to a gRPC target. TLS is not optional: the
    token is a bearer secret."""
    for scheme in ("https://", "grpcs://"):
        if url.startswith(scheme):
            url = url[len(scheme):]
            break
    else:
        if "://" in url:
            raise ValueError(f"control plane URL {url!r} must be host:port or https://host:port")
    url = url.rstrip("/")
    if not url or "/" in url:
        raise ValueError(f"control plane URL {url!r} must be host:port or https://host:port")
    return url


@dataclass(frozen=True)
class Placement:
    """A parsed ``Placement``. ``env_id`` and ``subenv`` are as the control plane sent
    them (possibly empty); the SDK dials with the names it was given, not these."""

    sandbox_id: _parse.SandboxId
    cell_id: str
    cell_address: _parse.CellAddress
    # Checked against the environment and sub-environment by Environment, which knows them.
    cell_name: str
    env_id: str
    subenv: str
    cold: bool
    cpu_halves: int
    memory_gib: int
    timeout_secs: int
    # PlaceSandbox's pass for this placement, which the cell checks at CreateSandbox; "" from
    # LocateSandbox.
    placement_pass: str = ""

    @classmethod
    def _from_proto(cls, msg: control_pb2.Placement) -> Placement:
        try:
            sandbox_id = _parse.sandbox_id(msg.sandbox_id)
            address = _parse.cell_address(msg.cell_address)
        except ValueError as err:
            raise ProtocolError(f"the control plane sent a bad placement: {err}") from None
        if not msg.cell_id:
            raise ProtocolError("the control plane sent a placement with no cell id")
        return cls(
            sandbox_id=sandbox_id,
            cell_id=msg.cell_id,
            cell_address=address,
            cell_name=msg.cell_name,
            env_id=msg.env_id,
            subenv=msg.subenv_id,
            cold=msg.cold,
            cpu_halves=msg.size.cpu_halves,
            memory_gib=msg.size.memory_gib,
            timeout_secs=msg.timeout_secs,
            placement_pass=msg.placement_pass,
        )


@dataclass(frozen=True)
class Pool:
    """A sub-environment's pool as the control plane holds it: the ``region`` its cells run
    in, the ``zones`` of that region it uses (the control plane's choice, every approved
    zone), warm cells per zone and the idle window."""

    subenv: str
    region: str
    zones: tuple[str, ...]
    min_warm_per_zone: int
    idle_window_secs: int

    @classmethod
    def _from_proto(cls, msg: control_pb2.Pool) -> Pool:
        return cls(
            subenv=msg.subenv_id,
            region=msg.region,
            zones=tuple(msg.zones),
            min_warm_per_zone=msg.min_warm_per_zone,
            idle_window_secs=msg.idle_window_secs,
        )


class Control:
    """A TLS channel to the control plane. Thread-safe."""

    def __init__(self, url: str, token: str, ca: Optional[bytes]) -> None:
        # ca None: gRPC's default roots (the system's, or GRPC_DEFAULT_SSL_ROOTS_FILE_PATH).
        self._channel = grpc.secure_channel(target(url), grpc.ssl_channel_credentials(root_certificates=ca))
        self._stub = control_pb2_grpc.ControlStub(self._channel)
        self._metadata = (("authorization", f"Bearer {token}"),)

    def place(
        self,
        env_id: str,
        subenv: str,
        cpu_halves: int,
        memory_gib: int,
        timeout_secs: int,
        avoid_cells: Sequence[str] = (),
    ) -> Placement:
        """``Control.PlaceSandbox``; zero sizes and timeout take the sub-environment's defaults."""
        request = control_pb2.PlaceSandboxRequest(
            env_id=env_id,
            subenv_id=subenv,
            size=control_pb2.Resources(cpu_halves=cpu_halves, memory_gib=memory_gib),
            timeout_secs=timeout_secs,
            avoid_cells=list(avoid_cells),
        )
        try:
            reply = self._stub.PlaceSandbox(request, timeout=PLACE_TIMEOUT_SECS, metadata=self._metadata)
        except grpc.RpcError as err:
            raise _control_error(err) from None
        return Placement._from_proto(reply)

    def put_pool(
        self, env_id: str, subenv: str, region: str, min_warm_per_zone: int, idle_window_secs: int
    ) -> Pool:
        """``Control.PutPool`` with the customer's fields; zero idle window is the default."""
        request = control_pb2.Pool(
            env_id=env_id,
            subenv_id=subenv,
            region=region,
            min_warm_per_zone=min_warm_per_zone,
            idle_window_secs=idle_window_secs,
        )
        try:
            reply = self._stub.PutPool(request, timeout=LOCATE_TIMEOUT_SECS, metadata=self._metadata)
        except grpc.RpcError as err:
            raise _control_error(err) from None
        return Pool._from_proto(reply)

    def locate(self, sandbox_id: str) -> Placement:
        """``Control.LocateSandbox``: the cell an existing sandbox lives on."""
        request = control_pb2.LocateSandboxRequest(sandbox_id=sandbox_id)
        try:
            reply = self._stub.LocateSandbox(request, timeout=LOCATE_TIMEOUT_SECS, metadata=self._metadata)
        except grpc.RpcError as err:
            raise _control_error(err) from None
        return Placement._from_proto(reply)

    def release(self, sandbox_id: str) -> None:
        """``Control.ReleaseSandbox``, best effort: a failure is swallowed, since the
        control plane also frees capacity on the sandbox's timeout and the cell's reports."""
        request = control_pb2.ReleaseSandboxRequest(sandbox_id=sandbox_id)
        try:
            self._stub.ReleaseSandbox(request, timeout=RELEASE_TIMEOUT_SECS, metadata=self._metadata)
        except grpc.RpcError:
            pass

    def put_credential(self, env_id: str, subenv: str, name: str, sealed: bytes) -> None:
        """``Control.PutCredential``: stores ciphertext sealed by the customer's verifier."""
        request = control_pb2.PutCredentialRequest(env_id=env_id, subenv_id=subenv, name=name, sealed=sealed)
        try:
            self._stub.PutCredential(request, timeout=LOCATE_TIMEOUT_SECS, metadata=self._metadata)
        except grpc.RpcError as err:
            raise _control_error(err) from None

    def put_template(self, header: control_pb2.TemplateHeader, data: Iterable[bytes]) -> Template:
        """``Control.PutTemplate``: the header, then ``data`` (ciphertext pieces) as data
        messages, pulled one at a time as gRPC sends them. If ``data`` raises, the call
        is cancelled and that exception is raised here."""
        failure: list[Exception] = []

        def requests() -> Iterator[control_pb2.PutTemplateRequest]:
            yield control_pb2.PutTemplateRequest(header=header)
            try:
                for piece in data:
                    yield control_pb2.PutTemplateRequest(data=piece)
            except Exception as err:
                # grpc cancels the call and reports only "Exception iterating requests!".
                failure.append(err)
                raise

        try:
            reply = self._stub.PutTemplate(requests(), timeout=UPLOAD_TIMEOUT_SECS, metadata=self._metadata)
        except grpc.RpcError as err:
            if failure:
                raise failure[0] from None
            raise _control_error(err) from None
        return Template._from_proto(reply.template)

    def get_template(self, env_id: str, subenv: str, name: str) -> Template:
        """``Control.GetTemplate``: a sub-environment's template by name."""
        request = control_pb2.GetTemplateRequest(env_id=env_id, subenv_id=subenv, name=name)
        try:
            reply = self._stub.GetTemplate(request, timeout=LOCATE_TIMEOUT_SECS, metadata=self._metadata)
        except grpc.RpcError as err:
            raise _control_error(err) from None
        return Template._from_proto(reply)

    def close(self) -> None:
        self._channel.close()
