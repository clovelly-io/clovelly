"""Parsing at the SDK's edges: caller arguments and control-plane answers become typed
values here, so the rest of the SDK can trust them.

Each parser raises ``ValueError``. For caller input that is the error the caller sees;
for control-plane answers ``_control`` turns it into ``ProtocolError``.
"""

from __future__ import annotations

import ipaddress
import math
import os
import re
from pathlib import Path
from typing import Mapping, NewType, Optional, Sequence, Union

# 32 lowercase hex characters (SPEC.md decision: fixed width, so prefix-free for runsc).
SandboxId = NewType("SandboxId", str)
# One DNS label: environment and sub-environment ids are parts of the cell's SAN.
Label = NewType("Label", str)
# "a.b.c.d:port", the cell's forwarding-rule address.
CellAddress = NewType("CellAddress", str)

PemSource = Union[str, bytes, "os.PathLike[str]"]
Command = Union[str, Sequence[str]]

MAX_TIMEOUT_SECS = 86_400
KEY_BYTES = 32
MAX_VOLUME_GIB = 20

_SANDBOX_ID = re.compile(r"[0-9a-f]{32}")
_CRED_NAME = re.compile(r"[a-z0-9_-]{1,64}")
_HOST_LABEL = re.compile(r"[a-z0-9_-]{1,63}")
ADAPTERS = ("bearer", "basic", "query")
PLACEHOLDER_PREFIX = "clovelly://cred/"
MAX_SECRET = 16 * 1024
_LABEL = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_TEMPLATE_NAME = re.compile(r"[a-z0-9_.-]{1,64}")
_VOLUME_NAME = re.compile(r"[a-z0-9_-]{1,64}")


def sandbox_id(value: object) -> SandboxId:
    if not isinstance(value, str) or not _SANDBOX_ID.fullmatch(value):
        raise ValueError(f"sandbox id {value!r} is not 32 lowercase hex characters")
    return SandboxId(value)


def label(value: object, what: str) -> Label:
    if not isinstance(value, str) or not _LABEL.fullmatch(value):
        raise ValueError(
            f"{what} {value!r} is not a DNS label (1-63 of a-z, 0-9, '-', "
            "no leading or trailing '-')"
        )
    return Label(value)


def cell_address(value: object) -> CellAddress:
    """``host:port`` with an IPv4 host: cells are dialled by forwarding-rule address,
    never by a name the SDK would have to resolve."""
    if not isinstance(value, str):
        raise ValueError(f"cell address {value!r} is not a string")
    host, sep, port = value.rpartition(":")
    try:
        ip = ipaddress.IPv4Address(host)
        number = int(port)
    except ValueError:
        raise ValueError(f"cell address {value!r} is not ipv4:port") from None
    if not sep or not 0 < number < 65_536 or not port.isdigit():
        raise ValueError(f"cell address {value!r} is not ipv4:port")
    return CellAddress(f"{ip}:{number}")


def access_key(value: Union[str, bytes]) -> bytes:
    """A sandbox's 32-byte access key, given as bytes or as the hex ``Sandbox.key``."""
    if isinstance(value, str):
        try:
            value = bytes.fromhex(value)
        except ValueError:
            raise ValueError("access key is not hex") from None
    if not isinstance(value, bytes) or len(value) != KEY_BYTES:
        raise ValueError(f"access key must be {KEY_BYTES} bytes ({2 * KEY_BYTES} hex characters)")
    return value


def pem(value: PemSource, what: str) -> bytes:
    """PEM certificates given inline (str or bytes) or as a path to a PEM file."""
    if isinstance(value, bytes):
        data = value
    elif isinstance(value, str) and "-----BEGIN" in value:
        data = value.encode("ascii")
    else:
        data = Path(value).read_bytes()
    if b"-----BEGIN CERTIFICATE-----" not in data:
        raise ValueError(f"{what} holds no PEM certificate")
    return data


def _number(value: object, what: str) -> Union[int, float]:
    # bool is an int; True vCPUs is a bug, not a size.
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{what} must be a number, not {value!r}")
    return value


def cpu_halves(cpu: Optional[float]) -> int:
    """vCPUs to the wire's halves (2 is one vCPU); None is 0, the sub-environment's
    default."""
    if cpu is None:
        return 0
    halves = _number(cpu, "cpu") * 2
    if not (math.isfinite(halves) and 0 < halves < 2**32 and halves == int(halves)):
        raise ValueError(f"cpu must be a positive multiple of 0.5 vCPU, not {cpu!r}")
    return int(halves)


def whole(value: Optional[int], what: str, maximum: int = 2**32 - 1) -> int:
    """A positive whole number up to ``maximum``; None is 0, the default."""
    if value is None:
        return 0
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= maximum:
        raise ValueError(f"{what} must be a whole number from 1 to {maximum}, not {value!r}")
    return value


def argv(command: Command) -> list[str]:
    """A shell string becomes ``/bin/sh -c <string>``; a sequence is argv as given."""
    if isinstance(command, str):
        return ["/bin/sh", "-c", command]
    args = list(command)
    if not args or not all(isinstance(arg, str) for arg in args):
        raise ValueError("command must be a string or a non-empty sequence of strings")
    return args


def string_map(value: Optional[Mapping[str, str]], what: str) -> dict[str, str]:
    if value is None:
        return {}
    items = dict(value)
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in items.items()):
        raise ValueError(f"{what} must map strings to strings")
    return items


def data(value: Union[bytes, bytearray, memoryview, str]) -> bytes:
    """Bytes to send; str is UTF-8."""
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise ValueError(f"expected bytes or str, not {type(value).__name__}")


def cred_name(value: object) -> str:
    """A credential name: 1-64 of a-z, 0-9, '_', '-'."""
    if not isinstance(value, str) or not _CRED_NAME.fullmatch(value):
        raise ValueError(f"credential name {value!r} is not 1-64 of a-z, 0-9, '_', '-'")
    return value


def adapter(value: object) -> str:
    if value not in ADAPTERS:
        raise ValueError(f"adapter {value!r} is not one of {', '.join(ADAPTERS)}")
    return str(value)


def host_name(value: object) -> str:
    """One named destination host (no wildcard), lower-cased."""
    if not isinstance(value, str):
        raise ValueError(f"destination {value!r} is not a host name")
    name = value.lower().rstrip(".")
    if not name or len(name) > 253 or not all(_HOST_LABEL.fullmatch(l) for l in name.split(".")):
        raise ValueError(f"destination {value!r} is not a host name (credentials are bound to one named host)")
    return name


def secret(value: Union[bytes, str]) -> bytes:
    raw = value.encode("utf-8") if isinstance(value, str) else bytes(value)
    if not raw or len(raw) > MAX_SECRET:
        raise ValueError("a credential secret must be 1 byte to 16 KiB")
    return raw


def is_digest(value: object) -> bool:
    """True for a template digest: SHA-256 as 64 lowercase hex characters."""
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def digest(value: object) -> str:
    if not is_digest(value):
        raise ValueError(f"template digest {value!r} is not 64 lowercase hex characters")
    return str(value)


def template_name(value: object) -> str:
    """A template name: 1-64 of a-z, 0-9, '_', '-', '.'."""
    if not isinstance(value, str) or not _TEMPLATE_NAME.fullmatch(value):
        raise ValueError(f"template name {value!r} is not 1-64 of a-z, 0-9, '_', '-', '.'")
    return value


def volume_name(value: object) -> str:
    """A volume name: 1-64 of a-z, 0-9, '_', '-'."""
    if not isinstance(value, str) or not _VOLUME_NAME.fullmatch(value):
        raise ValueError(f"volume name {value!r} is not 1-64 of a-z, 0-9, '_', '-'")
    return value
