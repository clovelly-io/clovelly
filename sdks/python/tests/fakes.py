"""In-process fakes for the SDK tests: certificates made with the openssl CLI, a fake
control plane, a fake customer verifier and fake cells serving the Cell and Health
services over TLS.

The fakes record every RPC that reaches them (through a server interceptor, so the
Health probe counts too) and the peer address of each, which identifies the TCP
connection a call arrived on.
"""

from __future__ import annotations

import functools
import json
import os
import secrets
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from concurrent import futures
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

import grpc
from grpc_health.v1 import health, health_pb2_grpc

import clovelly
from clovelly.cell.v1 import cell_pb2, cell_pb2_grpc
from clovelly.control.v1 import control_pb2, control_pb2_grpc
from clovelly.verifier.v1 import verifier_pb2, verifier_pb2_grpc

ENV_ID = "staging"
# Two cells of sub-environment a and one of b, by their own names (phase 12).
CELL_1 = f"cell-1.us-central1-a.a.{ENV_ID}.cells.clovelly.internal"
CELL_2 = f"cell-2.us-central1-a.a.{ENV_ID}.cells.clovelly.internal"
CELL_B = f"cell-1.us-central1-a.b.{ENV_ID}.cells.clovelly.internal"
TOKEN = "test-token"
VERIFIER_TOKEN = "sdk-token"
# The signature fake cells put on their receipts (the SDK does not verify it).
SIGNATURE = bytes(range(64))

# The tests configure the control plane explicitly; a developer's settings must not leak in.
for _var in ("CLOVELLY_API_URL", "CLOVELLY_API_TOKEN", "CLOVELLY_API_CA", "CLOVELLY_VERIFIER_TOKEN", "CLOVELLY_VERIFIER_CA"):
    os.environ.pop(_var, None)

_CA_EXT = """\
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
"""
_LEAF_EXT = """\
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = {san}
"""


class Pki:
    """Test certificates, EC P-256, in a temporary directory.

    CAs: ``env`` (the environment CA the SDK pins), ``other`` (another environment's),
    ``api`` (the control plane's). Leaves, each with a cell's two SANs as the verifier
    issues them: ``cell_a`` (env CA, sub-environment a and ``CELL_1``), ``cell_a2`` (env CA,
    a and ``CELL_2``, a second cell), ``cell_b`` (env CA, sub-environment b and ``CELL_B``),
    ``old_a`` (env CA, sub-environment a only, as before phase 12), ``self_signed`` and
    ``other_ca`` (both naming a and ``CELL_1``); ``control`` (api CA, 127.0.0.1).
    """

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="clovelly-sdk-pki-")
        self.dir = Path(self._tmp.name)
        for ca in ("env", "other", "api"):
            self._ca(ca)
        a = f"DNS:a.{ENV_ID}.cells.clovelly.internal"
        self._leaf("cell_a", f"{a}, DNS:{CELL_1}", "env")
        self._leaf("cell_a2", f"{a}, DNS:{CELL_2}", "env")
        self._leaf("cell_b", f"DNS:b.{ENV_ID}.cells.clovelly.internal, DNS:{CELL_B}", "env")
        self._leaf("old_a", a, "env")
        self._leaf("self_signed", f"{a}, DNS:{CELL_1}", None)
        self._leaf("other_ca", f"{a}, DNS:{CELL_1}", "other")
        self._leaf("control", "DNS:localhost, IP:127.0.0.1", "api")

    def cert(self, name: str) -> bytes:
        return (self.dir / f"{name}.pem").read_bytes()

    def key(self, name: str) -> bytes:
        return (self.dir / f"{name}.key").read_bytes()

    def der(self, name: str) -> bytes:
        return ssl.PEM_cert_to_DER_cert(self.cert(name).decode("ascii"))

    def server_credentials(self, name: str) -> grpc.ServerCredentials:
        return grpc.ssl_server_credentials([(self.key(name), self.cert(name))])

    def _openssl(self, *args: str) -> None:
        subprocess.run(["openssl", *args], cwd=self.dir, check=True, capture_output=True)

    def _csr(self, name: str) -> None:
        self._openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", f"{name}.key")
        self._openssl("req", "-new", "-key", f"{name}.key", "-subj", f"/CN={name}", "-out", f"{name}.csr")

    def _ca(self, name: str) -> None:
        self._csr(name)
        (self.dir / "ca.ext").write_text(_CA_EXT)
        self._openssl(
            "x509", "-req", "-in", f"{name}.csr", "-signkey", f"{name}.key", "-days", "2",
            "-sha256", "-extfile", "ca.ext", "-out", f"{name}.pem",
        )

    def _leaf(self, name: str, san: str, ca: Optional[str]) -> None:
        self._csr(name)
        (self.dir / f"{name}.ext").write_text(_LEAF_EXT.format(san=san))
        signer = (
            ["-signkey", f"{name}.key"]
            if ca is None
            else ["-CA", f"{ca}.pem", "-CAkey", f"{ca}.key", "-set_serial", str(secrets.randbits(63))]
        )
        self._openssl(
            "x509", "-req", "-in", f"{name}.csr", *signer, "-days", "2", "-sha256",
            "-extfile", f"{name}.ext", "-out", f"{name}.pem",
        )


@functools.lru_cache(maxsize=None)
def pki() -> Pki:
    """The process's certificates, made on first use."""
    return Pki()


def abort(
    context: grpc.ServicerContext, code: grpc.StatusCode, reason: str, *extra: tuple[str, str]
) -> None:
    """Ends a call the way the real services do: the reason in the clovelly-error trailer,
    and any ``extra`` trailers (NO_CAPACITY's region and retry-after, say)."""
    context.set_trailing_metadata((("clovelly-error", reason), *extra))
    context.abort(code, f"refused: {reason}")


class _Recorder(grpc.ServerInterceptor):
    def __init__(self, on_call: Callable[[str], None]) -> None:
        self._on_call = on_call

    def intercept_service(self, continuation, handler_call_details):
        self._on_call(handler_call_details.method.rsplit("/", 1)[-1])
        return continuation(handler_call_details)


def _serve(
    name: str, add: Callable[[grpc.Server], None], on_call: Callable[[str], None]
) -> tuple[grpc.Server, str]:
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=128), interceptors=[_Recorder(on_call)])
    add(server)
    port = server.add_secure_port("127.0.0.1:0", pki().server_credentials(name))
    server.start()
    return server, f"127.0.0.1:{port}"


@dataclass
class FakeSandbox:
    request: cell_pb2.CreateSandboxRequest
    files: dict[str, bytes] = field(default_factory=dict)
    ended: Optional[int] = None  # an ExitKind once ended
    execs: int = 0


class FakeCell(cell_pb2_grpc.CellServicer):
    """A cell serving Cell and Health over TLS with the named certificate.

    Exec understands a few commands: ``/bin/sh -c "python3 -c 'print(6*7)'"`` prints
    42, ``cat`` echoes stdin, ``wait-for-all`` blocks until ``barrier`` is full (to hold
    many streams open at once), ``exit N`` exits with N; anything else prints its argv.
    """

    def __init__(self, cert: str = "cell_a", cell_id: str = "cell-1", name: str = CELL_1) -> None:
        self.cell_id = cell_id
        # The name the control plane places by; the certificate may say otherwise.
        self.name = name
        self.calls: list[str] = []
        self.peers: set[str] = set()
        self.sandboxes: dict[str, FakeSandbox] = {}
        self.refuse_create: Optional[tuple[grpc.StatusCode, str]] = None
        self.barrier: Optional[threading.Barrier] = None
        self._lock = threading.Lock()
        self._server, self.address = _serve(cert, self._add, self._record)

    def _add(self, server: grpc.Server) -> None:
        cell_pb2_grpc.add_CellServicer_to_server(self, server)
        health_pb2_grpc.add_HealthServicer_to_server(health.HealthServicer(), server)

    def _record(self, method: str) -> None:
        with self._lock:
            self.calls.append(method)

    def stop(self) -> None:
        self._server.stop(None)

    def _sandbox(self, sandbox_id: str, key: bytes, context: grpc.ServicerContext) -> FakeSandbox:
        self.peers.add(context.peer())
        sandbox = self.sandboxes.get(sandbox_id)
        if sandbox is None:
            abort(context, grpc.StatusCode.NOT_FOUND, "NO_SUCH_SANDBOX")
        if key != sandbox.request.access_key:
            abort(context, grpc.StatusCode.PERMISSION_DENIED, "PERMISSION")
        return sandbox

    def _receipt(self, sandbox_id: str, sandbox: FakeSandbox) -> cell_pb2.Receipt:
        kind = sandbox.ended or cell_pb2.EXIT_KIND_RUNNING
        name = clovelly._receipts.exit_kind_name(kind)
        request = sandbox.request
        body = {
            "v": 1,
            "env": ENV_ID,
            "sandbox": {"id": sandbox_id, "template_digest": request.template_digest or None, "volume_id": request.volume or None},
            "exit": {"kind": name},
        }
        return cell_pb2.Receipt(
            json=json.dumps(body, sort_keys=True, separators=(",", ":")).encode(),
            signature=SIGNATURE,
            exit_kind=kind,
            cell_cert=pki().der("cell_a"),
            final=sandbox.ended is not None,
        )

    def CreateSandbox(self, request, context):
        self.peers.add(context.peer())
        if self.refuse_create is not None:
            abort(context, *self.refuse_create)
        if request.sandbox_id in self.sandboxes:
            abort(context, grpc.StatusCode.ALREADY_EXISTS, "SANDBOX_EXISTS")
        self.sandboxes[request.sandbox_id] = FakeSandbox(request)
        return cell_pb2.CreateSandboxResponse(started_unix_ms=int(time.time() * 1000), runsc_ms=7)

    def Exec(self, request_iterator, context):
        start = next(request_iterator).start
        sandbox = self._sandbox(start.sandbox_id, start.access_key, context)
        stdin = bytearray()
        for request in request_iterator:
            if request.WhichOneof("msg") == "stdin_eof":
                break
            stdin += request.stdin
        sandbox.execs += 1
        first_exec_ms = 123 if sandbox.execs == 1 else 0
        args = list(start.args)
        code = 0
        if args == ["/bin/sh", "-c", "python3 -c 'print(6*7)'"]:
            out = b"42\n"
        elif args == ["cat"]:
            out = bytes(stdin)
        elif args == ["wait-for-all"]:
            assert self.barrier is not None
            self.barrier.wait()
            out = start.sandbox_id.encode()
        elif args[:1] == ["exit"]:
            out, code = b"", int(args[1])
        else:
            out = " ".join(args).encode()
        for offset in range(0, max(len(out), 1), 64 * 1024):
            yield cell_pb2.ExecResponse(stdout=out[offset : offset + 64 * 1024])
        yield cell_pb2.ExecResponse(stderr=b"err")
        yield cell_pb2.ExecResponse(exit=cell_pb2.ExecExit(code=code, first_exec_ms=first_exec_ms))

    def ReadFile(self, request, context):
        sandbox = self._sandbox(request.sandbox_id, request.access_key, context)
        data = sandbox.files.get(request.path)
        if data is None:
            abort(context, grpc.StatusCode.NOT_FOUND, "NO_SUCH_FILE")
        for offset in range(0, len(data), 64 * 1024):
            yield cell_pb2.FileChunk(data=data[offset : offset + 64 * 1024])

    def WriteFile(self, request_iterator, context):
        header = next(request_iterator).header
        sandbox = self._sandbox(header.sandbox_id, header.access_key, context)
        data = b"".join(request.data for request in request_iterator)
        sandbox.files[header.path] = data
        return cell_pb2.WriteFileResponse(bytes_written=len(data))

    def Kill(self, request, context):
        sandbox = self._sandbox(request.sandbox_id, request.access_key, context)
        if sandbox.ended is not None:
            abort(context, grpc.StatusCode.FAILED_PRECONDITION, "SANDBOX_ENDED")
        sandbox.ended = cell_pb2.EXIT_KIND_KILLED
        return self._receipt(request.sandbox_id, sandbox)

    def GetReceipt(self, request, context):
        sandbox = self._sandbox(request.sandbox_id, request.access_key, context)
        return self._receipt(request.sandbox_id, sandbox)


@dataclass
class Upload:
    """One PutTemplate stream as the fake control plane received it."""

    header: control_pb2.TemplateHeader
    data: list[bytes]


class FakeControl(control_pb2_grpc.ControlServicer):
    """A control plane that places each sandbox on the first of ``cells`` not in
    ``avoid_cells``, filling defaults (1 vCPU, 2 GiB, 900 s), and stores templates whose
    upload stream completed (by name, in ``templates``; every stream in ``uploads``)."""

    def __init__(self, cells: list[FakeCell]) -> None:
        self.cells = cells
        self.calls: list[str] = []
        self.places: list[control_pb2.PlaceSandboxRequest] = []
        self.released: list[str] = []
        self.tokens: set[str] = set()
        self.placed: dict[str, FakeCell] = {}
        self.refuse_place: Optional[tuple] = None
        # A cell name to place with instead of the cell's own (a control plane naming another cell).
        self.name_override: Optional[str] = None
        self.regions = ("us-central1", "europe-west4", "asia-southeast1")
        self.pools: dict[str, control_pb2.Pool] = {}
        self.uploads: list[Upload] = []
        self.templates: dict[tuple[str, str], control_pb2.TemplateInfo] = {}
        self._server, self.address = _serve(
            "control", lambda s: control_pb2_grpc.add_ControlServicer_to_server(self, s), self.calls.append
        )

    def stop(self) -> None:
        self._server.stop(None)

    def _auth(self, context: grpc.ServicerContext) -> None:
        metadata = dict(context.invocation_metadata())
        self.tokens.add(metadata.get("authorization", ""))
        if metadata.get("authorization") != f"Bearer {TOKEN}":
            abort(context, grpc.StatusCode.UNAUTHENTICATED, "UNAUTHENTICATED")

    def _placement(self, sandbox_id: str, cell: FakeCell, size: control_pb2.Resources, timeout: int) -> control_pb2.Placement:
        return control_pb2.Placement(
            sandbox_id=sandbox_id,
            cell_id=cell.cell_id,
            cell_address=cell.address,
            cell_name=self.name_override or cell.name,
            env_id=ENV_ID,
            subenv_id="a",
            cold=False,
            size=size,
            timeout_secs=timeout,
            placement_pass=f"clp1.fake.{cell.cell_id}",
        )

    def PlaceSandbox(self, request, context):
        self._auth(context)
        self.places.append(request)
        if self.refuse_place is not None:
            abort(context, *self.refuse_place)
        cell = next((c for c in self.cells if c.cell_id not in request.avoid_cells), None)
        if cell is None:
            abort(context, grpc.StatusCode.FAILED_PRECONDITION, "NO_CELL_CAN_HOLD")
        sandbox_id = secrets.token_hex(16)
        self.placed[sandbox_id] = cell
        size = control_pb2.Resources(
            cpu_halves=request.size.cpu_halves or 2, memory_gib=request.size.memory_gib or 2
        )
        return self._placement(sandbox_id, cell, size, request.timeout_secs or 900)

    def PutPool(self, request, context):
        self._auth(context)
        if request.region not in self.regions:
            abort(context, grpc.StatusCode.INVALID_ARGUMENT, "UNKNOWN_REGION", ("clovelly-regions", ",".join(self.regions)))
        pool = control_pb2.Pool()
        pool.CopyFrom(request)
        pool.zones.extend(f"{request.region}-{z}" for z in "abc")
        self.pools[request.subenv_id] = pool
        return pool

    def LocateSandbox(self, request, context):
        self._auth(context)
        cell = self.placed.get(request.sandbox_id)
        if cell is None:
            abort(context, grpc.StatusCode.NOT_FOUND, "NO_SUCH_SANDBOX")
        return self._placement(request.sandbox_id, cell, control_pb2.Resources(cpu_halves=2, memory_gib=2), 900)

    def ReleaseSandbox(self, request, context):
        self._auth(context)
        self.released.append(request.sandbox_id)
        return control_pb2.ReleaseSandboxResponse()

    def PutTemplate(self, request_iterator, context):
        self._auth(context)
        first = next(request_iterator)
        if first.WhichOneof("msg") != "header":
            abort(context, grpc.StatusCode.INVALID_ARGUMENT, "INVALID_REQUEST")
        upload = Upload(first.header, [])
        self.uploads.append(upload)
        # A cancelled stream raises here, and nothing is stored.
        upload.data.extend(request.data for request in request_iterator)
        header = upload.header
        info = control_pb2.TemplateInfo(
            name=header.name,
            digest=header.digest,
            ciphertext_bytes=sum(map(len, upload.data)),
            plaintext_bytes=header.plaintext_bytes,
            parts=1,
        )
        self.templates[(header.subenv_id, header.name)] = info
        return control_pb2.PutTemplateResponse(template=info)

    def GetTemplate(self, request, context):
        self._auth(context)
        info = self.templates.get((request.subenv_id, request.name))
        if info is None:
            abort(context, grpc.StatusCode.NOT_FOUND, "NO_SUCH_TEMPLATE")
        return info


class FakeVerifier(verifier_pb2_grpc.VerifierServicer):
    """The customer's verifier, for the SDK's calls. SealTemplateKey always issues
    ``KEY`` (so tests can decrypt what was uploaded) with ``b"sealed:" + digest``;
    ListReceipts serves ``log`` filtered as asked; GetEgressLog serves ``egress``."""

    KEY = bytes(range(32))

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.requests: list[object] = []
        self.tokens: set[str] = set()
        self.log: list[verifier_pb2.LoggedReceipt] = []
        self.egress: dict[str, verifier_pb2.GetEgressLogResponse] = {}
        self._server, self.address = _serve(
            "control", lambda s: verifier_pb2_grpc.add_VerifierServicer_to_server(self, s), self.calls.append
        )

    @property
    def url(self) -> str:
        return f"https://{self.address}"

    def stop(self) -> None:
        self._server.stop(None)

    def _auth(self, request: object, context: grpc.ServicerContext) -> None:
        self.requests.append(request)
        token = dict(context.invocation_metadata()).get("authorization", "")
        self.tokens.add(token)
        if token != f"Bearer {VERIFIER_TOKEN}":
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "bad SDK token")

    def SealTemplateKey(self, request, context):
        self._auth(request, context)
        return verifier_pb2.SealTemplateKeyResponse(key=self.KEY, sealed_key=b"sealed:" + request.digest.encode())

    def ListReceipts(self, request, context):
        self._auth(request, context)

        def wanted(record: verifier_pb2.LoggedReceipt) -> bool:
            doc = json.loads(record.receipt)
            return (not request.subenv_id or doc.get("subenv") == request.subenv_id) and (
                not request.sandbox_ids or doc["sandbox"]["id"] in request.sandbox_ids
            )

        return verifier_pb2.ListReceiptsResponse(receipts=[r for r in self.log if wanted(r)])

    def GetEgressLog(self, request, context):
        self._auth(request, context)
        reply = self.egress.get(request.sandbox_id)
        if reply is None:
            context.abort(grpc.StatusCode.NOT_FOUND, "no final receipt for that sandbox")
        return reply


def environment(control: Optional[FakeControl] = None, verifier: Optional[FakeVerifier] = None) -> clovelly.Environment:
    """An Environment pinning the test environment CA, pointed at ``control`` and
    ``verifier``."""
    return clovelly.Environment(
        verifier.url if verifier else "https://verifier.invalid",
        ENV_ID,
        pki().cert("env"),
        api_url=control.address if control else None,
        api_token=TOKEN if control else None,
        api_ca=pki().cert("api") if control else None,
        verifier_token=VERIFIER_TOKEN if verifier else None,
        verifier_ca=pki().cert("api") if verifier else None,
    )


class Services(unittest.TestCase):
    """A cell, a control plane over it, the customer's verifier and an Environment on
    all three, fresh for each test."""

    def setUp(self) -> None:
        self.cell = FakeCell()
        self.addCleanup(self.cell.stop)
        self.control = FakeControl([self.cell])
        self.addCleanup(self.control.stop)
        self.verifier = FakeVerifier()
        self.addCleanup(self.verifier.stop)
        self.env = environment(self.control, self.verifier)
        self.addCleanup(self.env.close)
