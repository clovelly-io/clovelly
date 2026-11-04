"""Python SDK for the confidential agent runtime.

Sandboxes run under gVisor inside Intel TDX cells. The SDK trusts only the environment
CA from the customer's own verifier: it sends nothing to a cell whose TLS certificate
does not chain to that CA and name the sub-environment it asked for.

    import clovelly

    env = clovelly.Environment(verifier_url, env_id, ca_bundle)
    tpl = env.upload_template("bank-a", "analyst-v3", "analyst-v3.tar.gz")
    sb = env.sandbox("bank-a", template=tpl, volume="work", cpu=1, memory=2, timeout=900)
    r = sb.exec("python3 -c 'print(6*7)'")
    r = sb.exec("python3 call.py", env={"API_KEY": sb.cred("svc")})  # a placeholder
    sb.files.write("/tmp/x", b"data")
    receipt = sb.close()                       # signed; also in the customer's log
    log = env.egress_log(sb.id)
    assert log.matches(receipt)

See README.md for the connection rules, the error types and the environment variables.
"""

from ._cell import Cell, ExecResult
from ._receipts import EgressLog, LoggedReceipt, Receipt, egress_log_sha256
from ._template import Template
from .environment import Environment, Files, Sandbox, placeholder
from .errors import (
    AbovePolicyMaximum,
    CapacityError,
    ClovellyError,
    CellCreateFailed,
    CellDraining,
    CellRevoked,
    CellUnavailable,
    CellVerificationError,
    ControlPlaneUnavailable,
    CredentialUnavailable,
    CrossesCellEnd,
    CrossesReleaseExpiry,
    EgressLogMismatch,
    FileNotFound,
    InvalidRequest,
    InvalidSandboxId,
    NoCellCanHold,
    NoCellReady,
    QuotaExceeded,
    NoSuchCell,
    NoSuchEnvironment,
    NoSuchPool,
    NoSuchSubenvironment,
    NoSuchTemplate,
    PermissionDenied,
    PolicyRefused,
    ProtocolError,
    RuntimeFailure,
    SandboxEnded,
    SandboxExists,
    SandboxNotFound,
    StorageUnavailable,
    TemplateUnavailable,
    Unauthenticated,
    VerificationKind,
    VerifierUnavailable,
    VolumeBusy,
    VolumeUnavailable,
    VolumeUnreadable,
)

__version__ = "0.4.0"

__all__ = [
    "Environment",
    "Sandbox",
    "Files",
    "placeholder",
    "Cell",
    "ExecResult",
    "Receipt",
    "LoggedReceipt",
    "EgressLog",
    "egress_log_sha256",
    "Template",
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
    "QuotaExceeded",
    "CellCreateFailed",
    "CellVerificationError",
    "CellUnavailable",
    "ControlPlaneUnavailable",
    "ProtocolError",
    "EgressLogMismatch",
    "VerificationKind",
]
