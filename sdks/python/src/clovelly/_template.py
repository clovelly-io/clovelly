"""Templates: a sandbox root (a gzipped tar) uploaded once per sub-environment and
encrypted by the SDK, so only that sub-environment's cells can open it (SPEC.md
"Credentials and templates are stored as ciphertext we cannot read").

The customer's verifier issues a fresh key for the template's digest and the same key
sealed under the sub-environment DEK (``SealTemplateKey``). The SDK encrypts with the key
and streams the ciphertext and the sealed key to the control plane (``PutTemplate``).

The ciphertext format is ``crates/common/src/template.rs``'s, byte for byte: one record
per 1 MiB of plaintext (the last may be shorter; an empty template is one empty chunk; a
template that is a whole number of chunks marks its last full chunk), each a 4-byte
big-endian length and then AES-256-GCM of the chunk (ciphertext and 16-byte tag) with
nonce ``0^4 || index (u64 BE)`` and associated data ``"clovelly-v1 template chunk" ||
digest (32 bytes) || index (u64 BE) || last (one byte)``.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import BinaryIO, Iterable, Iterator, Optional, Union

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from clovelly.control.v1 import control_pb2

from . import _parse
from .errors import ProtocolError

__all__ = ["Template", "CHUNK_BYTES", "DATA_BYTES", "file_digest", "encrypt", "pieces", "ciphertext"]

# Plaintext bytes per chunk.
CHUNK_BYTES = 1 << 20
KEY_BYTES = 32
# Ciphertext bytes per PutTemplate data message: 4 MiB less room for the message's own
# framing, so each message stays within gRPC's default 4 MiB limit on what a server takes.
DATA_BYTES = (4 << 20) - 64
_AAD = b"clovelly-v1 template chunk"

Path = Union[str, "os.PathLike[str]"]


@dataclass(frozen=True)
class Template:
    """A sub-environment's template, as the control plane stores it.

    ``digest`` is the SHA-256 of the plaintext, lowercase hex: what ``CreateSandbox`` and
    the sandbox's receipt name. ``ciphertext_bytes``, ``plaintext_bytes`` and ``parts``
    (64 MiB ciphertext objects) are the stored sizes. Pass a Template, or its digest, as
    ``Environment.sandbox(template=...)``.
    """

    name: str
    digest: str
    ciphertext_bytes: int
    plaintext_bytes: int
    parts: int

    @classmethod
    def _from_proto(cls, msg: control_pb2.TemplateInfo) -> Template:
        try:
            name = _parse.template_name(msg.name)
            digest = _parse.digest(msg.digest)
        except ValueError as err:
            raise ProtocolError(f"the control plane sent a bad template: {err}") from None
        return cls(
            name=name,
            digest=digest,
            ciphertext_bytes=msg.ciphertext_bytes,
            plaintext_bytes=msg.plaintext_bytes,
            parts=msg.parts,
        )


def _chunks(source: BinaryIO) -> Iterator[bytes]:
    """``source`` in 1 MiB pieces; an empty source is one empty piece."""
    chunk = source.read(CHUNK_BYTES)
    yield chunk
    while chunk:
        chunk = source.read(CHUNK_BYTES)
        if chunk:
            yield chunk


def file_digest(path: Path) -> tuple[bytes, int]:
    """The SHA-256 of the file at ``path`` and its size, read 1 MiB at a time."""
    hasher = hashlib.sha256()
    size = 0
    with open(path, "rb") as source:
        for chunk in _chunks(source):
            hasher.update(chunk)
            size += len(chunk)
    return hasher.digest(), size


def _nonce(index: int) -> bytes:
    return bytes(4) + index.to_bytes(8, "big")


def _aad(digest: bytes, index: int, last: bool) -> bytes:
    return _AAD + digest + index.to_bytes(8, "big") + (b"\x01" if last else b"\x00")


def encrypt(key: bytes, digest: bytes, chunks: Iterable[bytes]) -> Iterator[bytes]:
    """Encrypts a template given as its plaintext chunks (1 MiB each but the last, at
    least one), yielding one record per chunk. ``digest`` is the plaintext's raw 32-byte
    SHA-256. It reads one chunk ahead to know which chunk is the last."""
    if len(key) != KEY_BYTES or len(digest) != 32:
        raise ValueError("a template key and digest are 32 bytes each")
    aead = AESGCM(key)
    pending = iter(chunks)
    current: Optional[bytes] = next(pending, b"")
    index = 0
    while current is not None:
        following = next(pending, None)
        last = following is None
        sealed = aead.encrypt(_nonce(index), current, _aad(digest, index, last))
        yield len(sealed).to_bytes(4, "big") + sealed
        current = following
        index += 1


def pieces(records: Iterable[bytes], size: int = DATA_BYTES) -> Iterator[bytes]:
    """The concatenation of ``records`` cut into pieces of ``size`` bytes, the last
    shorter: the ciphertext of PutTemplate's data messages."""
    buffer = bytearray()
    for record in records:
        buffer += record
        while len(buffer) >= size:
            yield bytes(buffer[:size])
            del buffer[:size]
    if buffer:
        yield bytes(buffer)


def ciphertext(path: Path, key: bytes, digest: bytes, size: int) -> Iterator[bytes]:
    """The file at ``path`` encrypted, in data-message pieces, reading it 1 MiB at a time.

    ``digest`` and ``size`` are what :func:`file_digest` found. If the file no longer has
    them, this raises ``ValueError`` before the last chunk is encrypted, so the upload is
    cancelled rather than finished with a template that does not match its digest.
    """

    def checked() -> Iterator[bytes]:
        hasher = hashlib.sha256()
        read = 0
        with open(path, "rb") as source:
            for chunk in _chunks(source):
                hasher.update(chunk)
                read += len(chunk)
                if read > size:
                    break
                yield chunk
        if read != size or hasher.digest() != digest:
            raise ValueError(f"template file {os.fspath(path)!r} changed while it was being uploaded")

    yield from pieces(encrypt(key, digest, checked()))
