from google.protobuf.internal import containers as _containers
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class GetNonceRequest(_message.Message):
    __slots__ = ("env_id",)
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    def __init__(self, env_id: _Optional[str] = ...) -> None: ...

class GetNonceResponse(_message.Message):
    __slots__ = ("nonce",)
    NONCE_FIELD_NUMBER: _ClassVar[int]
    nonce: bytes
    def __init__(self, nonce: _Optional[bytes] = ...) -> None: ...

class Evidence(_message.Message):
    __slots__ = ("quote", "ccel_table", "ccel_log", "env_id", "subenv_id", "release_id", "spki", "nonce", "instance_id", "zone")
    QUOTE_FIELD_NUMBER: _ClassVar[int]
    CCEL_TABLE_FIELD_NUMBER: _ClassVar[int]
    CCEL_LOG_FIELD_NUMBER: _ClassVar[int]
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    SUBENV_ID_FIELD_NUMBER: _ClassVar[int]
    RELEASE_ID_FIELD_NUMBER: _ClassVar[int]
    SPKI_FIELD_NUMBER: _ClassVar[int]
    NONCE_FIELD_NUMBER: _ClassVar[int]
    INSTANCE_ID_FIELD_NUMBER: _ClassVar[int]
    ZONE_FIELD_NUMBER: _ClassVar[int]
    quote: bytes
    ccel_table: bytes
    ccel_log: bytes
    env_id: str
    subenv_id: str
    release_id: str
    spki: bytes
    nonce: bytes
    instance_id: int
    zone: str
    def __init__(self, quote: _Optional[bytes] = ..., ccel_table: _Optional[bytes] = ..., ccel_log: _Optional[bytes] = ..., env_id: _Optional[str] = ..., subenv_id: _Optional[str] = ..., release_id: _Optional[str] = ..., spki: _Optional[bytes] = ..., nonce: _Optional[bytes] = ..., instance_id: _Optional[int] = ..., zone: _Optional[str] = ...) -> None: ...

class UnlockRequest(_message.Message):
    __slots__ = ("evidence",)
    EVIDENCE_FIELD_NUMBER: _ClassVar[int]
    evidence: Evidence
    def __init__(self, evidence: _Optional[_Union[Evidence, _Mapping]] = ...) -> None: ...

class UnlockResponse(_message.Message):
    __slots__ = ("cell_cert", "wrapped_env_dek", "policy_bundle", "policy_sig", "release_valid_until", "policy_key")
    CELL_CERT_FIELD_NUMBER: _ClassVar[int]
    WRAPPED_ENV_DEK_FIELD_NUMBER: _ClassVar[int]
    POLICY_BUNDLE_FIELD_NUMBER: _ClassVar[int]
    POLICY_SIG_FIELD_NUMBER: _ClassVar[int]
    RELEASE_VALID_UNTIL_FIELD_NUMBER: _ClassVar[int]
    POLICY_KEY_FIELD_NUMBER: _ClassVar[int]
    cell_cert: bytes
    wrapped_env_dek: bytes
    policy_bundle: bytes
    policy_sig: str
    release_valid_until: int
    policy_key: str
    def __init__(self, cell_cert: _Optional[bytes] = ..., wrapped_env_dek: _Optional[bytes] = ..., policy_bundle: _Optional[bytes] = ..., policy_sig: _Optional[str] = ..., release_valid_until: _Optional[int] = ..., policy_key: _Optional[str] = ...) -> None: ...

class GetCARequest(_message.Message):
    __slots__ = ("env_id",)
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    def __init__(self, env_id: _Optional[str] = ...) -> None: ...

class GetCAResponse(_message.Message):
    __slots__ = ("ca_cert", "previous_ca_certs")
    CA_CERT_FIELD_NUMBER: _ClassVar[int]
    PREVIOUS_CA_CERTS_FIELD_NUMBER: _ClassVar[int]
    ca_cert: bytes
    previous_ca_certs: _containers.RepeatedScalarFieldContainer[bytes]
    def __init__(self, ca_cert: _Optional[bytes] = ..., previous_ca_certs: _Optional[_Iterable[bytes]] = ...) -> None: ...

class GetPolicyRequest(_message.Message):
    __slots__ = ("env_id", "subenv_id")
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    SUBENV_ID_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    subenv_id: str
    def __init__(self, env_id: _Optional[str] = ..., subenv_id: _Optional[str] = ...) -> None: ...

class GetPolicyResponse(_message.Message):
    __slots__ = ("policy_bundle", "policy_sig")
    POLICY_BUNDLE_FIELD_NUMBER: _ClassVar[int]
    POLICY_SIG_FIELD_NUMBER: _ClassVar[int]
    policy_bundle: bytes
    policy_sig: str
    def __init__(self, policy_bundle: _Optional[bytes] = ..., policy_sig: _Optional[str] = ...) -> None: ...

class SealCredentialRequest(_message.Message):
    __slots__ = ("env_id", "subenv_id", "name", "adapter", "destination", "secret")
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    SUBENV_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    ADAPTER_FIELD_NUMBER: _ClassVar[int]
    DESTINATION_FIELD_NUMBER: _ClassVar[int]
    SECRET_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    subenv_id: str
    name: str
    adapter: str
    destination: str
    secret: bytes
    def __init__(self, env_id: _Optional[str] = ..., subenv_id: _Optional[str] = ..., name: _Optional[str] = ..., adapter: _Optional[str] = ..., destination: _Optional[str] = ..., secret: _Optional[bytes] = ...) -> None: ...

class SealCredentialResponse(_message.Message):
    __slots__ = ("sealed",)
    SEALED_FIELD_NUMBER: _ClassVar[int]
    sealed: bytes
    def __init__(self, sealed: _Optional[bytes] = ...) -> None: ...

class SealTemplateKeyRequest(_message.Message):
    __slots__ = ("env_id", "subenv_id", "digest")
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    SUBENV_ID_FIELD_NUMBER: _ClassVar[int]
    DIGEST_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    subenv_id: str
    digest: str
    def __init__(self, env_id: _Optional[str] = ..., subenv_id: _Optional[str] = ..., digest: _Optional[str] = ...) -> None: ...

class SealTemplateKeyResponse(_message.Message):
    __slots__ = ("key", "sealed_key")
    KEY_FIELD_NUMBER: _ClassVar[int]
    SEALED_KEY_FIELD_NUMBER: _ClassVar[int]
    key: bytes
    sealed_key: bytes
    def __init__(self, key: _Optional[bytes] = ..., sealed_key: _Optional[bytes] = ...) -> None: ...

class LogRecord(_message.Message):
    __slots__ = ("receipt", "signature", "cell_cert", "final", "egress_log")
    RECEIPT_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    CELL_CERT_FIELD_NUMBER: _ClassVar[int]
    FINAL_FIELD_NUMBER: _ClassVar[int]
    EGRESS_LOG_FIELD_NUMBER: _ClassVar[int]
    receipt: bytes
    signature: bytes
    cell_cert: bytes
    final: bool
    egress_log: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, receipt: _Optional[bytes] = ..., signature: _Optional[bytes] = ..., cell_cert: _Optional[bytes] = ..., final: bool = ..., egress_log: _Optional[_Iterable[str]] = ...) -> None: ...

class AppendReceiptRequest(_message.Message):
    __slots__ = ("records",)
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    records: _containers.RepeatedCompositeFieldContainer[LogRecord]
    def __init__(self, records: _Optional[_Iterable[_Union[LogRecord, _Mapping]]] = ...) -> None: ...

class AppendReceiptResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ListReceiptsRequest(_message.Message):
    __slots__ = ("env_id", "subenv_id", "sandbox_ids")
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    SUBENV_ID_FIELD_NUMBER: _ClassVar[int]
    SANDBOX_IDS_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    subenv_id: str
    sandbox_ids: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, env_id: _Optional[str] = ..., subenv_id: _Optional[str] = ..., sandbox_ids: _Optional[_Iterable[str]] = ...) -> None: ...

class LoggedReceipt(_message.Message):
    __slots__ = ("receipt", "signature", "cell_cert", "final", "received_unix_ms", "records", "finals")
    RECEIPT_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    CELL_CERT_FIELD_NUMBER: _ClassVar[int]
    FINAL_FIELD_NUMBER: _ClassVar[int]
    RECEIVED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    RECORDS_FIELD_NUMBER: _ClassVar[int]
    FINALS_FIELD_NUMBER: _ClassVar[int]
    receipt: bytes
    signature: bytes
    cell_cert: bytes
    final: bool
    received_unix_ms: int
    records: int
    finals: int
    def __init__(self, receipt: _Optional[bytes] = ..., signature: _Optional[bytes] = ..., cell_cert: _Optional[bytes] = ..., final: bool = ..., received_unix_ms: _Optional[int] = ..., records: _Optional[int] = ..., finals: _Optional[int] = ...) -> None: ...

class ListReceiptsResponse(_message.Message):
    __slots__ = ("receipts",)
    RECEIPTS_FIELD_NUMBER: _ClassVar[int]
    receipts: _containers.RepeatedCompositeFieldContainer[LoggedReceipt]
    def __init__(self, receipts: _Optional[_Iterable[_Union[LoggedReceipt, _Mapping]]] = ...) -> None: ...

class GetEgressLogRequest(_message.Message):
    __slots__ = ("env_id", "sandbox_id")
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    sandbox_id: str
    def __init__(self, env_id: _Optional[str] = ..., sandbox_id: _Optional[str] = ...) -> None: ...

class GetEgressLogResponse(_message.Message):
    __slots__ = ("lines", "sha256")
    LINES_FIELD_NUMBER: _ClassVar[int]
    SHA256_FIELD_NUMBER: _ClassVar[int]
    lines: _containers.RepeatedScalarFieldContainer[str]
    sha256: str
    def __init__(self, lines: _Optional[_Iterable[str]] = ..., sha256: _Optional[str] = ...) -> None: ...
