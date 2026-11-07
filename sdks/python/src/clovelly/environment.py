"""The public surface: an :class:`Environment` makes and reconnects :class:`Sandbox` es.

::

    env = clovelly.Environment(verifier_url, env_id, ca_bundle)
    env.put_pool("bank-a", region="europe-west4")   # once: where bank-a's cells run
    env.put_credential("bank-a", "openai", api_key, adapter="bearer", destination="api.openai.com")
    tpl = env.upload_template("bank-a", "analyst-v3", "analyst-v3.tar.gz")
    with env.sandbox("bank-a", template=tpl, volume="work", cpu=1, memory=2, timeout=900) as sb:
        r = sb.exec("python3 -c 'print(6*7)'")
        r = sb.exec("python3 call.py", env={"OPENAI_API_KEY": sb.cred("openai")})
        sb.files.write("/tmp/in.txt", b"hello")
        data = sb.files.read("/tmp/in.txt")
    # leaving the block closes the sandbox; sb.close() returns its signed receipt
    logged = env.receipts("bank-a", sandbox_ids=[sb.id])
    log = env.egress_log(sb.id)              # its hash already checked
    assert log.matches(logged[0])
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from types import TracebackType
from typing import Mapping, Optional, Sequence, Tuple, Type, Union

from clovelly.control.v1 import control_pb2

from . import _parse, _template
from ._cell import Cell, ExecResult
from ._control import Control, Placement, Pool
from ._receipts import EgressLog, LoggedReceipt, Receipt
from ._template import Template
from ._verifier import Verifier
from .errors import (
    CapacityError,
    ClovellyError,
    CellDraining,
    CellRevoked,
    CrossesCellEnd,
    CrossesReleaseExpiry,
    ProtocolError,
    SandboxEnded,
)

__all__ = ["Environment", "Sandbox", "Files", "placeholder"]

# A cell that refuses a create for one of these reasons is avoided and the sandbox
# placed again, up to MAX_PLACEMENTS placements in all.
_REPLACE_ON: Tuple[Type[ClovellyError], ...] = (
    CapacityError,
    CrossesCellEnd,
    CrossesReleaseExpiry,
    CellDraining,
    CellRevoked,
)
MAX_PLACEMENTS = 3


def placeholder(name: str) -> str:
    """The placeholder a sandbox carries for credential ``name``: ``clovelly://cred/<name>``.
    The egress proxy replaces it with the real secret only in requests to the
    credential's destination; anywhere else it is just a string."""
    return _parse.PLACEHOLDER_PREFIX + _parse.cred_name(name)


def _ms(since: float) -> float:
    return (time.perf_counter() - since) * 1000.0


class Environment:
    """One customer environment, as its own verifier vouches for it.

    ``ca_bundle`` is the environment CA (PEM as str or bytes, or a path to a PEM file),
    from the customer's verifier (``GetCA``). It is the only trust anchor for cells: a
    cell's certificate must chain to it and name ``<subenv>.<env_id>.cells.clovelly.internal``.
    ``env_id`` is the environment's id (a DNS label). ``verifier_url`` is the customer's
    verifier (``https://host[:port]``), which seals credentials (:meth:`put_credential`)
    and template keys (:meth:`upload_template`) and keeps the receipt log
    (:meth:`receipts`, :meth:`egress_log`). Those calls need the verifier's SDK token,
    ``verifier_token`` (default ``CLOVELLY_VERIFIER_TOKEN``); ``verifier_ca`` (PEM or a path,
    default ``CLOVELLY_VERIFIER_CA``) replaces the system roots for its certificate.

    The control plane is a service setting, not a trust input: ``api_url`` (``host:port``
    or ``https://host:port``), ``api_token`` and ``api_ca`` (its CA as PEM or a path;
    unset uses the system roots) default to ``CLOVELLY_API_URL``, ``CLOVELLY_API_TOKEN`` and
    ``CLOVELLY_API_CA``. They are needed only by :meth:`sandbox` and :meth:`reconnect`.

    Thread-safe: many threads may share one Environment. It keeps one TLS connection
    per cell, shared by every sandbox on that cell. Close it with :meth:`close` or use
    it as a context manager.
    """

    def __init__(
        self,
        verifier_url: str,
        env_id: str,
        ca_bundle: _parse.PemSource,
        *,
        api_url: Optional[str] = None,
        api_token: Optional[str] = None,
        api_ca: Optional[_parse.PemSource] = None,
        verifier_token: Optional[str] = None,
        verifier_ca: Optional[_parse.PemSource] = None,
    ) -> None:
        self.verifier_url = verifier_url
        self._verifier_token = verifier_token or os.environ.get("CLOVELLY_VERIFIER_TOKEN") or None
        verifier_ca = verifier_ca or os.environ.get("CLOVELLY_VERIFIER_CA") or None
        self._verifier_ca = _parse.pem(verifier_ca, "verifier_ca") if verifier_ca else None
        self._verifier_client: Optional[Verifier] = None
        self.env_id = _parse.label(env_id, "environment id")
        self._ca = _parse.pem(ca_bundle, "ca_bundle")
        self._api_url = api_url or os.environ.get("CLOVELLY_API_URL") or None
        self._api_token = api_token or os.environ.get("CLOVELLY_API_TOKEN") or None
        api_ca = api_ca or os.environ.get("CLOVELLY_API_CA") or None
        self._api_ca = _parse.pem(api_ca, "api_ca") if api_ca else None
        self._lock = threading.Lock()
        self._cells: dict[tuple[str, str], Cell] = {}
        self._control_client: Optional[Control] = None

    def __enter__(self) -> Environment:
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        self.close()

    def sandbox(
        self,
        subenv: str,
        *,
        template: Union[Template, str, None] = None,
        policy: None = None,
        volume: Optional[str] = None,
        volume_gib: Optional[int] = None,
        timeout: Optional[int] = None,
        cpu: Optional[float] = None,
        memory: Optional[int] = None,
        command: Optional[_parse.Command] = None,
        env: Optional[Mapping[str, str]] = None,
    ) -> Sandbox:
        """Creates a sandbox in sub-environment ``subenv``.

        ``cpu`` is in vCPUs, a multiple of 0.5; ``memory`` in GiB; ``timeout`` in seconds,
        at most 86400. None takes the sub-environment's default (1 vCPU, 2 GiB, 900 s
        unless its policy says otherwise). ``command`` is the sandbox's optional main
        process (a shell string or an argv list; the sandbox ends when it exits) and
        ``env`` its environment.

        ``template`` is the sandbox's read-only root: a :class:`Template`, its digest (64
        lowercase hex characters) or its name, which the control plane resolves in
        ``subenv`` (pass the Template or digest to pin the exact content). None is the
        base bundle. ``volume`` names a persistent volume of the sub-environment (1-64 of
        a-z, 0-9, '_', '-'), mounted at ``/volume`` and created on first use with
        ``volume_gib`` GiB (1 to 20, default 1); one sandbox mounts it at a time.
        ``policy`` must be None: a sub-environment has one policy bundle.

        The control plane places the sandbox (blocking while a cell boots if none is
        warm), the SDK verifies the cell, then creates the sandbox there with a fresh
        32-byte access key. A cell that refuses for capacity, its cap, its release's
        expiry, a drain or a revoked lease is avoided and the sandbox placed again, up to
        three placements; the last refusal is raised if all three refuse.
        """
        if policy is not None:
            raise ValueError("policy must be None: a sub-environment has one policy bundle")
        sub = _parse.label(subenv, "sub-environment id")
        # Every argument is parsed before the first call; a template named rather than
        # given by digest is looked up just before placing.
        template_digest = ""
        template_by_name: Optional[str] = None
        if isinstance(template, Template):
            template_digest = _parse.digest(template.digest)
        elif _parse.is_digest(template):
            template_digest = str(template)
        elif template is not None:
            template_by_name = _parse.template_name(template)
        volume_name = _parse.volume_name(volume) if volume is not None else ""
        if volume_gib is not None and volume is None:
            raise ValueError("volume_gib needs a volume")
        gib = _parse.whole(volume_gib, "volume_gib (GiB)", _parse.MAX_VOLUME_GIB)
        halves = _parse.cpu_halves(cpu)
        memory_gib = _parse.whole(memory, "memory (GiB)")
        timeout_secs = _parse.whole(timeout, "timeout (seconds)", _parse.MAX_TIMEOUT_SECS)
        main = _parse.argv(command) if command is not None else []
        main_env = _parse.string_map(env, "env")
        control = self._control()
        if template_by_name is not None:
            template_digest = control.get_template(self.env_id, sub, template_by_name).digest

        timings = {"place_ms": 0.0, "connect_ms": 0.0, "create_ms": 0.0}
        avoid: list[str] = []
        refusal: Optional[ClovellyError] = None
        for _ in range(MAX_PLACEMENTS):
            started = time.perf_counter()
            placement = control.place(self.env_id, sub, halves, memory_gib, timeout_secs, avoid)
            timings["place_ms"] += _ms(started)
            try:
                self._check(placement, sub)
                started = time.perf_counter()
                cell, cached = self._connect(placement.cell_address, sub)
                timings["connect_ms"] += 0.0 if cached else _ms(started)
                key = os.urandom(_parse.KEY_BYTES)
                started = time.perf_counter()
                created = cell.create_sandbox(
                    placement.sandbox_id,
                    key,
                    placement.cpu_halves,
                    placement.memory_gib,
                    placement.timeout_secs,
                    main,
                    main_env,
                    template_digest=template_digest,
                    volume=volume_name,
                    volume_gib=gib,
                )
                timings["create_ms"] += _ms(started)
            except _REPLACE_ON as err:
                control.release(placement.sandbox_id)
                avoid.append(placement.cell_id)
                refusal = err
                continue
            except Exception:
                control.release(placement.sandbox_id)
                raise
            timings["runsc_ms"] = float(created.runsc_ms)
            return Sandbox._placed(self, cell, placement, key, timings)
        assert refusal is not None, "the loop runs at least once"
        raise refusal

    def reconnect(
        self, sandbox_id: str, key: Union[str, bytes], *, subenv: Optional[str] = None
    ) -> Sandbox:
        """Reattaches to an existing sandbox by id and access key (``Sandbox.id`` and
        ``Sandbox.key``), from this or any other process.

        The control plane says which cell holds it; the SDK verifies that cell and
        confirms with ``GetReceipt``, which only succeeds for the right key. Pass
        ``subenv`` to require the sandbox to be in that sub-environment.
        """
        sid = _parse.sandbox_id(sandbox_id)
        key_bytes = _parse.access_key(key)
        expected = _parse.label(subenv, "sub-environment id") if subenv is not None else None
        timings: dict[str, float] = {}

        started = time.perf_counter()
        placement = self._control().locate(sid)
        timings["locate_ms"] = _ms(started)
        if placement.sandbox_id != sid:
            raise ProtocolError(f"asked for sandbox {sid}, the control plane located {placement.sandbox_id}")
        if placement.subenv:
            try:
                sub = _parse.label(placement.subenv, "sub-environment id")
            except ValueError as err:
                raise ProtocolError(f"the control plane sent a bad placement: {err}") from None
            if expected is not None and sub != expected:
                raise ProtocolError(f"sandbox {sid} is in sub-environment {sub!r}, not {expected!r}")
        elif expected is not None:
            sub = expected
        else:
            raise ProtocolError(f"the control plane located {sid} without a sub-environment; pass subenv=")
        self._check(placement, sub)

        started = time.perf_counter()
        cell, cached = self._connect(placement.cell_address, sub)
        timings["connect_ms"] = 0.0 if cached else _ms(started)
        started = time.perf_counter()
        cell.get_receipt(sid, key_bytes)
        timings["receipt_ms"] = _ms(started)
        return Sandbox._placed(self, cell, placement, key_bytes, timings)

    def put_pool(
        self, subenv: str, region: str, *, min_warm_per_zone: int = 0, idle_window_secs: int = 0
    ) -> Pool:
        """Sets ``subenv``'s pool: the ``region`` its cells run in, from the published list
        (docs/regions.md), warm cells per zone, and the idle window (0 is the default,
        15 minutes). The control plane uses every approved zone of the region and moves
        cells between them when one runs out of machines; when all of them have,
        :meth:`sandbox` raises :class:`NoCapacity` rather than queue or go elsewhere.
        A region is fixed once set: another region is another sub-environment. Raises
        :class:`UnknownRegion` (with ``.regions``, the list) for a region not offered.
        """
        sub = _parse.label(subenv, "sub-environment id")
        if min_warm_per_zone < 0 or idle_window_secs < 0:
            raise ValueError("min_warm_per_zone and idle_window_secs must not be negative")
        return self._control().put_pool(self.env_id, sub, region, min_warm_per_zone, idle_window_secs)

    def put_credential(
        self,
        subenv: str,
        name: str,
        secret: Union[bytes, str],
        *,
        adapter: str,
        destination: str,
    ) -> None:
        """Stores credential ``name`` for ``subenv``'s sandboxes, valid only for
        ``destination`` (one named host) with ``adapter`` (``"bearer"``, ``"basic"`` or
        ``"query"``, as the sub-environment's policy uses it there).

        The customer's verifier seals the secret under the sub-environment DEK, bound to
        the name, adapter and destination; the control plane stores only that
        ciphertext. Sandboxes see ``placeholder(name)``; a cell releases the secret to
        its egress proxy at sandbox start. Replaces a credential of the same name.
        """
        sub = _parse.label(subenv, "sub-environment id")
        cred = _parse.cred_name(name)
        kind = _parse.adapter(adapter)
        host = _parse.host_name(destination)
        raw = _parse.secret(secret)
        sealed = self._verifier().seal(self.env_id, sub, cred, kind, host, raw)
        self._control().put_credential(self.env_id, sub, cred, sealed)

    def upload_template(self, subenv: str, name: str, path: _template.Path) -> Template:
        """Uploads the template at ``path`` (the ``.tar.gz`` of a sandbox root) to
        ``subenv`` as ``name`` (1-64 of a-z, 0-9, '_', '-', '.'), replacing a template of
        that name, and returns it.

        The SDK reads the file twice, 1 MiB at a time: once for its SHA-256 (the digest),
        then to encrypt and stream it. The customer's verifier issues a key for that
        digest (``SealTemplateKey``, with the SDK token) together with the key sealed
        under the sub-environment DEK; the control plane receives only the ciphertext and
        the sealed key, so only the sub-environment's cells can open it. A file that
        changes between the two reads cancels the upload with ``ValueError``.
        """
        sub = _parse.label(subenv, "sub-environment id")
        tpl_name = _parse.template_name(name)
        verifier, control = self._verifier(), self._control()
        digest, size = _template.file_digest(path)
        key, sealed_key = verifier.seal_template_key(self.env_id, sub, digest.hex())
        header = control_pb2.TemplateHeader(
            env_id=self.env_id,
            subenv_id=sub,
            name=tpl_name,
            digest=digest.hex(),
            sealed_key=sealed_key,
            plaintext_bytes=size,
        )
        stored = control.put_template(header, _template.ciphertext(path, key, digest, size))
        if (stored.name, stored.digest) != (tpl_name, digest.hex()):
            raise ProtocolError(
                f"uploaded template {tpl_name} ({digest.hex()}), the control plane stored "
                f"{stored.name} ({stored.digest})"
            )
        return stored

    def template(self, subenv: str, name: str) -> Template:
        """The template ``name`` of ``subenv``, as the control plane stores it
        (``NoSuchTemplate`` if there is none)."""
        sub = _parse.label(subenv, "sub-environment id")
        return self._control().get_template(self.env_id, sub, _parse.template_name(name))

    def receipts(
        self, subenv: Optional[str] = None, *, sandbox_ids: Optional[Sequence[str]] = None
    ) -> list[LoggedReceipt]:
        """The customer's receipt log at the verifier (``ListReceipts``, with the SDK
        token): the latest record per sandbox, for ``subenv`` (None: every
        sub-environment) and ``sandbox_ids`` (None: every sandbox)."""
        sub = _parse.label(subenv, "sub-environment id") if subenv is not None else ""
        ids = [_parse.sandbox_id(sid) for sid in sandbox_ids or ()]
        return self._verifier().list_receipts(self.env_id, sub, ids)

    def egress_log(self, sandbox_id: str) -> EgressLog:
        """The egress log a sandbox's final receipt carried, from the verifier
        (``GetEgressLog``, with the SDK token). Raises ``EgressLogMismatch`` unless its
        lines hash to the SHA-256 the verifier sent with them; ``EgressLog.matches``
        then checks that against a receipt's ``egress_log_hash``."""
        return self._verifier().egress_log(self.env_id, _parse.sandbox_id(sandbox_id))

    def cell(self, address: str, subenv: str) -> Cell:
        """The shared connection to the cell at ``address`` (``host:port``, IPv4) for
        ``subenv``, created on first use. It is verified on its first call; call
        ``.verify()`` to do that explicitly. A connection closed by a refusal is
        replaced by a fresh one here."""
        addr = _parse.cell_address(address)
        sub = _parse.label(subenv, "sub-environment id")
        with self._lock:
            cell = self._cells.get((addr, sub))
            if cell is None or cell.closed:
                cell = Cell(addr, self.env_id, sub, self._ca)
                self._cells[(addr, sub)] = cell
            return cell

    def close(self) -> None:
        """Closes every cell connection and the control-plane channel. Sandboxes keep
        running; :meth:`reconnect` reaches them again."""
        with self._lock:
            cells, self._cells = list(self._cells.values()), {}
            control, self._control_client = self._control_client, None
            verifier, self._verifier_client = self._verifier_client, None
        for cell in cells:
            cell.close()
        if control is not None:
            control.close()
        if verifier is not None:
            verifier.close()

    def _connect(self, address: _parse.CellAddress, subenv: _parse.Label) -> tuple[Cell, bool]:
        """The verified connection to a cell, and whether it was already verified."""
        cell = self.cell(address, subenv)
        cached = cell.verified
        cell.verify()
        return cell, cached

    def _check(self, placement: Placement, subenv: str) -> None:
        if placement.env_id and placement.env_id != self.env_id:
            raise ProtocolError(f"placement is for environment {placement.env_id!r}, not {self.env_id!r}")
        if placement.subenv and placement.subenv != subenv:
            raise ProtocolError(f"placement is for sub-environment {placement.subenv!r}, not {subenv!r}")

    def _control(self) -> Control:
        with self._lock:
            if self._control_client is None:
                if not self._api_url or not self._api_token:
                    raise ValueError(
                        "the control plane is not configured: pass api_url and api_token "
                        "or set CLOVELLY_API_URL and CLOVELLY_API_TOKEN"
                    )
                self._control_client = Control(self._api_url, self._api_token, self._api_ca)
            return self._control_client

    def _verifier(self) -> Verifier:
        with self._lock:
            if self._verifier_client is None:
                if not self._verifier_token:
                    raise ValueError(
                        "calls to the verifier need its SDK token: pass verifier_token or set CLOVELLY_VERIFIER_TOKEN"
                    )
                self._verifier_client = Verifier(self.verifier_url, self._verifier_token, self._verifier_ca)
            return self._verifier_client

    def _release(self, sandbox_id: str) -> None:
        self._control().release(sandbox_id)


@dataclass(frozen=True, eq=False)
class Sandbox:
    """A sandbox on one cell. Made by ``Environment.sandbox`` or ``Environment.reconnect``.

    ``id`` and ``key`` (hex) are all another process needs to reconnect. ``cpu`` (vCPUs),
    ``memory`` (GiB) and ``timeout`` (seconds) are what was placed, defaults filled in.
    ``cold`` is True when a cell had to boot for it. ``timings`` holds milliseconds:
    ``place_ms``, ``connect_ms`` (0 when the cell's connection was already verified),
    ``create_ms`` (each summed over re-placements) and the cell's ``runsc_ms``; for a
    reconnected sandbox ``locate_ms``, ``connect_ms`` and ``receipt_ms``.

    Thread-safe; use it as a context manager to close it on exit.
    """

    id: str
    cell_id: str
    cell_address: str
    subenv: str
    cold: bool
    cpu: float
    memory: int
    timeout: int
    timings: dict[str, float]
    _key: bytes = field(repr=False)
    _cell: Cell = field(repr=False, compare=False)
    _env: Environment = field(repr=False, compare=False)

    @classmethod
    def _placed(
        cls, env: Environment, cell: Cell, placement: Placement, key: bytes, timings: dict[str, float]
    ) -> Sandbox:
        return cls(
            id=placement.sandbox_id,
            cell_id=placement.cell_id,
            cell_address=placement.cell_address,
            subenv=cell.subenv,
            cold=placement.cold,
            cpu=placement.cpu_halves / 2,
            memory=placement.memory_gib,
            timeout=placement.timeout_secs,
            timings=timings,
            _key=key,
            _cell=cell,
            _env=env,
        )

    @property
    def key(self) -> str:
        """The access key, hex. A secret: the cell keeps only its SHA-256 and the control
        plane never sees it."""
        return self._key.hex()

    @property
    def files(self) -> Files:
        return Files(self)

    def __enter__(self) -> Sandbox:
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        self.close()

    def exec(
        self,
        command: _parse.Command,
        *,
        stdin: Union[bytes, str, None] = None,
        env: Optional[Mapping[str, str]] = None,
        cwd: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> ExecResult:
        """Runs ``command`` (a shell string, run as ``/bin/sh -c``, or an argv list) and
        waits for it to exit. ``stdin`` (bytes, or str as UTF-8) is sent then closed;
        ``cwd`` defaults to ``/``; ``timeout`` (seconds) kills the process, otherwise only
        the sandbox's own timeout applies."""
        return self._cell.exec(
            self.id,
            self._key,
            _parse.argv(command),
            stdin=_parse.data(stdin) if stdin is not None else b"",
            env=_parse.string_map(env, "env"),
            cwd=cwd or "",
            timeout_secs=_parse.whole(timeout, "timeout (seconds)"),
        )

    def close(self) -> Receipt:
        """Kills the sandbox and returns its final signed receipt (the one it ended with
        if it had already ended), then tells the control plane its capacity is free (best
        effort). The cell has already appended the receipt to the customer's log."""
        try:
            receipt = self._cell.kill(self.id, self._key)
        except SandboxEnded:
            receipt = self._cell.get_receipt(self.id, self._key)
        self._env._release(self.id)
        return receipt

    def receipt(self) -> Receipt:
        """The sandbox's signed receipt: interim (``exit_kind == "running"``, ``final``
        False) while it runs, final once it has ended."""
        return self._cell.get_receipt(self.id, self._key)

    def cred(self, name: str) -> str:
        """The placeholder for credential ``name`` (``clovelly://cred/<name>``), to pass to
        the sandbox in place of the secret, for example in ``exec(env=...)``."""
        return placeholder(name)


class Files:
    """File access in one sandbox, as ``sb.files``."""

    def __init__(self, sandbox: Sandbox) -> None:
        self._sandbox = sandbox

    def write(self, path: str, data: Union[bytes, str]) -> int:
        """Writes ``data`` (bytes, or str as UTF-8) to the absolute ``path``, whose parent
        directory must exist. Returns the bytes written."""
        sb = self._sandbox
        return sb._cell.write_file(sb.id, sb._key, path, _parse.data(data))

    def read(self, path: str) -> bytes:
        """The contents of ``path``; raises ``FileNotFound`` if it is missing or unreadable."""
        sb = self._sandbox
        return sb._cell.read_file(sb.id, sb._key, path)
