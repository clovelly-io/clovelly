"""The customer's verifier, as the SDK calls it: ``SealCredential``, ``SealTemplateKey``,
``ListReceipts`` and ``GetEgressLog``, each authenticated by the SDK token.

The verifier is the customer's own service (Cloud Run, public TLS). The SDK sends it a
credential's secret and gets back ciphertext sealed under the sub-environment DEK and
bound to the credential's name, adapter type and destination; for a template it gets a
fresh key and that key sealed to the sub-environment. The SDK never holds a DEK. The
receipt log the verifier keeps is read back with the same token.
"""

from __future__ import annotations

from typing import Optional, Sequence
from urllib.parse import urlsplit

import grpc

from clovelly.verifier.v1 import verifier_pb2, verifier_pb2_grpc

from ._receipts import EgressLog, LoggedReceipt
from ._template import KEY_BYTES
from .errors import ProtocolError, SandboxNotFound, _verifier_error

__all__ = ["Verifier"]

SEAL_TIMEOUT_SECS = 30.0
READ_TIMEOUT_SECS = 30.0


def target(url: str) -> str:
    """``https://host[:port]`` to a gRPC target ``host:port``."""
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname or parts.path not in ("", "/"):
        raise ValueError(f"verifier URL {url!r} must be https://host[:port]")
    return f"{parts.hostname}:{parts.port or 443}"


class Verifier:
    """A TLS channel to the verifier, trusting ``ca`` (PEM) or, when None, the system
    roots. Thread-safe."""

    def __init__(self, url: str, token: str, ca: Optional[bytes] = None) -> None:
        self._channel = grpc.secure_channel(target(url), grpc.ssl_channel_credentials(root_certificates=ca))
        self._stub = verifier_pb2_grpc.VerifierStub(self._channel)
        self._metadata = (("authorization", f"Bearer {token}"),)

    def seal(self, env_id: str, subenv: str, name: str, adapter: str, destination: str, secret: bytes) -> bytes:
        """``Verifier.SealCredential``: the sealed credential (JSON bytes)."""
        request = verifier_pb2.SealCredentialRequest(
            env_id=env_id, subenv_id=subenv, name=name, adapter=adapter, destination=destination, secret=secret
        )
        try:
            return self._stub.SealCredential(request, timeout=SEAL_TIMEOUT_SECS, metadata=self._metadata).sealed
        except grpc.RpcError as err:
            raise _verifier_error(err) from None

    def seal_template_key(self, env_id: str, subenv: str, digest: str) -> tuple[bytes, bytes]:
        """``Verifier.SealTemplateKey``: a fresh 32-byte key for the template with this
        digest, and the same key sealed under the sub-environment DEK (opaque bytes)."""
        request = verifier_pb2.SealTemplateKeyRequest(env_id=env_id, subenv_id=subenv, digest=digest)
        try:
            reply = self._stub.SealTemplateKey(request, timeout=SEAL_TIMEOUT_SECS, metadata=self._metadata)
        except grpc.RpcError as err:
            raise _verifier_error(err) from None
        if len(reply.key) != KEY_BYTES or not reply.sealed_key:
            raise ProtocolError(f"the verifier sent a {len(reply.key)}-byte template key, or no sealed key")
        return reply.key, reply.sealed_key

    def list_receipts(self, env_id: str, subenv: str, sandbox_ids: Sequence[str]) -> list[LoggedReceipt]:
        """``Verifier.ListReceipts``; empty ``subenv`` and ``sandbox_ids`` mean all."""
        request = verifier_pb2.ListReceiptsRequest(env_id=env_id, subenv_id=subenv, sandbox_ids=list(sandbox_ids))
        try:
            reply = self._stub.ListReceipts(request, timeout=READ_TIMEOUT_SECS, metadata=self._metadata)
        except grpc.RpcError as err:
            raise _verifier_error(err) from None
        return [LoggedReceipt._from_proto(msg) for msg in reply.receipts]

    def egress_log(self, env_id: str, sandbox_id: str) -> EgressLog:
        """``Verifier.GetEgressLog``, its hash checked over its lines."""
        request = verifier_pb2.GetEgressLogRequest(env_id=env_id, sandbox_id=sandbox_id)
        try:
            reply = self._stub.GetEgressLog(request, timeout=READ_TIMEOUT_SECS, metadata=self._metadata)
        except grpc.RpcError as err:
            raise _verifier_error(err, SandboxNotFound) from None
        return EgressLog._from_proto(sandbox_id, reply)

    def close(self) -> None:
        self._channel.close()
