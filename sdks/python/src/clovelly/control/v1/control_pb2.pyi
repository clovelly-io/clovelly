from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class ErrorReason(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    ERROR_REASON_UNSPECIFIED: _ClassVar[ErrorReason]
    UNAUTHENTICATED: _ClassVar[ErrorReason]
    PERMISSION: _ClassVar[ErrorReason]
    INVALID_REQUEST: _ClassVar[ErrorReason]
    NO_SUCH_ENVIRONMENT: _ClassVar[ErrorReason]
    NO_SUCH_SUBENVIRONMENT: _ClassVar[ErrorReason]
    NO_SUCH_POOL: _ClassVar[ErrorReason]
    NO_SUCH_SANDBOX: _ClassVar[ErrorReason]
    NO_SUCH_CELL: _ClassVar[ErrorReason]
    ABOVE_POLICY_MAXIMUM: _ClassVar[ErrorReason]
    NO_CELL_CAN_HOLD: _ClassVar[ErrorReason]
    NO_CELL_READY: _ClassVar[ErrorReason]
    CELL_CREATE_FAILED: _ClassVar[ErrorReason]
    STORAGE: _ClassVar[ErrorReason]
    NO_SUCH_TEMPLATE: _ClassVar[ErrorReason]
    VOLUME_BUSY: _ClassVar[ErrorReason]

class DrainState(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DRAIN_STATE_UNSPECIFIED: _ClassVar[DrainState]
    SERVING: _ClassVar[DrainState]
    DRAINING: _ClassVar[DrainState]
    RECYCLE: _ClassVar[DrainState]
ERROR_REASON_UNSPECIFIED: ErrorReason
UNAUTHENTICATED: ErrorReason
PERMISSION: ErrorReason
INVALID_REQUEST: ErrorReason
NO_SUCH_ENVIRONMENT: ErrorReason
NO_SUCH_SUBENVIRONMENT: ErrorReason
NO_SUCH_POOL: ErrorReason
NO_SUCH_SANDBOX: ErrorReason
NO_SUCH_CELL: ErrorReason
ABOVE_POLICY_MAXIMUM: ErrorReason
NO_CELL_CAN_HOLD: ErrorReason
NO_CELL_READY: ErrorReason
CELL_CREATE_FAILED: ErrorReason
STORAGE: ErrorReason
NO_SUCH_TEMPLATE: ErrorReason
VOLUME_BUSY: ErrorReason
DRAIN_STATE_UNSPECIFIED: DrainState
SERVING: DrainState
DRAINING: DrainState
RECYCLE: DrainState

class PutEnvironmentRequest(_message.Message):
    __slots__ = ("env_id", "verifier_url", "ca_pem")
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    VERIFIER_URL_FIELD_NUMBER: _ClassVar[int]
    CA_PEM_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    verifier_url: str
    ca_pem: str
    def __init__(self, env_id: _Optional[str] = ..., verifier_url: _Optional[str] = ..., ca_pem: _Optional[str] = ...) -> None: ...

class PutEnvironmentResponse(_message.Message):
    __slots__ = ("token",)
    TOKEN_FIELD_NUMBER: _ClassVar[int]
    token: str
    def __init__(self, token: _Optional[str] = ...) -> None: ...

class Resources(_message.Message):
    __slots__ = ("cpu_halves", "memory_gib")
    CPU_HALVES_FIELD_NUMBER: _ClassVar[int]
    MEMORY_GIB_FIELD_NUMBER: _ClassVar[int]
    cpu_halves: int
    memory_gib: int
    def __init__(self, cpu_halves: _Optional[int] = ..., memory_gib: _Optional[int] = ...) -> None: ...

class Subenvironment(_message.Message):
    __slots__ = ("env_id", "subenv_id", "default_size", "max_size", "max_timeout_secs", "verifier_url")
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    SUBENV_ID_FIELD_NUMBER: _ClassVar[int]
    DEFAULT_SIZE_FIELD_NUMBER: _ClassVar[int]
    MAX_SIZE_FIELD_NUMBER: _ClassVar[int]
    MAX_TIMEOUT_SECS_FIELD_NUMBER: _ClassVar[int]
    VERIFIER_URL_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    subenv_id: str
    default_size: Resources
    max_size: Resources
    max_timeout_secs: int
    verifier_url: str
    def __init__(self, env_id: _Optional[str] = ..., subenv_id: _Optional[str] = ..., default_size: _Optional[_Union[Resources, _Mapping]] = ..., max_size: _Optional[_Union[Resources, _Mapping]] = ..., max_timeout_secs: _Optional[int] = ..., verifier_url: _Optional[str] = ...) -> None: ...

class Pool(_message.Message):
    __slots__ = ("env_id", "subenv_id", "machine_type", "zones", "min_warm_per_zone", "idle_window_secs", "cap_secs", "release_id", "test_metadata")
    class TestMetadataEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    SUBENV_ID_FIELD_NUMBER: _ClassVar[int]
    MACHINE_TYPE_FIELD_NUMBER: _ClassVar[int]
    ZONES_FIELD_NUMBER: _ClassVar[int]
    MIN_WARM_PER_ZONE_FIELD_NUMBER: _ClassVar[int]
    IDLE_WINDOW_SECS_FIELD_NUMBER: _ClassVar[int]
    CAP_SECS_FIELD_NUMBER: _ClassVar[int]
    RELEASE_ID_FIELD_NUMBER: _ClassVar[int]
    TEST_METADATA_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    subenv_id: str
    machine_type: str
    zones: _containers.RepeatedScalarFieldContainer[str]
    min_warm_per_zone: int
    idle_window_secs: int
    cap_secs: int
    release_id: str
    test_metadata: _containers.ScalarMap[str, str]
    def __init__(self, env_id: _Optional[str] = ..., subenv_id: _Optional[str] = ..., machine_type: _Optional[str] = ..., zones: _Optional[_Iterable[str]] = ..., min_warm_per_zone: _Optional[int] = ..., idle_window_secs: _Optional[int] = ..., cap_secs: _Optional[int] = ..., release_id: _Optional[str] = ..., test_metadata: _Optional[_Mapping[str, str]] = ...) -> None: ...

class GetPoolRequest(_message.Message):
    __slots__ = ("env_id", "subenv_id")
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    SUBENV_ID_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    subenv_id: str
    def __init__(self, env_id: _Optional[str] = ..., subenv_id: _Optional[str] = ...) -> None: ...

class PoolStatus(_message.Message):
    __slots__ = ("pool", "cells")
    POOL_FIELD_NUMBER: _ClassVar[int]
    CELLS_FIELD_NUMBER: _ClassVar[int]
    pool: Pool
    cells: _containers.RepeatedCompositeFieldContainer[CellStatus]
    def __init__(self, pool: _Optional[_Union[Pool, _Mapping]] = ..., cells: _Optional[_Iterable[_Union[CellStatus, _Mapping]]] = ...) -> None: ...

class CellStatus(_message.Message):
    __slots__ = ("cell_id", "zone", "instance_name", "state", "address", "release_id", "create_called_unix_ms", "ready_unix_ms", "deleted_unix_ms", "cell_end_unix", "sandbox_count", "unreserved", "recycle_reason", "forwarding_rule")
    CELL_ID_FIELD_NUMBER: _ClassVar[int]
    ZONE_FIELD_NUMBER: _ClassVar[int]
    INSTANCE_NAME_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    ADDRESS_FIELD_NUMBER: _ClassVar[int]
    RELEASE_ID_FIELD_NUMBER: _ClassVar[int]
    CREATE_CALLED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    READY_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    DELETED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    CELL_END_UNIX_FIELD_NUMBER: _ClassVar[int]
    SANDBOX_COUNT_FIELD_NUMBER: _ClassVar[int]
    UNRESERVED_FIELD_NUMBER: _ClassVar[int]
    RECYCLE_REASON_FIELD_NUMBER: _ClassVar[int]
    FORWARDING_RULE_FIELD_NUMBER: _ClassVar[int]
    cell_id: str
    zone: str
    instance_name: str
    state: str
    address: str
    release_id: str
    create_called_unix_ms: int
    ready_unix_ms: int
    deleted_unix_ms: int
    cell_end_unix: int
    sandbox_count: int
    unreserved: Resources
    recycle_reason: str
    forwarding_rule: str
    def __init__(self, cell_id: _Optional[str] = ..., zone: _Optional[str] = ..., instance_name: _Optional[str] = ..., state: _Optional[str] = ..., address: _Optional[str] = ..., release_id: _Optional[str] = ..., create_called_unix_ms: _Optional[int] = ..., ready_unix_ms: _Optional[int] = ..., deleted_unix_ms: _Optional[int] = ..., cell_end_unix: _Optional[int] = ..., sandbox_count: _Optional[int] = ..., unreserved: _Optional[_Union[Resources, _Mapping]] = ..., recycle_reason: _Optional[str] = ..., forwarding_rule: _Optional[str] = ...) -> None: ...

class PlaceSandboxRequest(_message.Message):
    __slots__ = ("env_id", "subenv_id", "size", "timeout_secs", "avoid_cells")
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    SUBENV_ID_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_SECS_FIELD_NUMBER: _ClassVar[int]
    AVOID_CELLS_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    subenv_id: str
    size: Resources
    timeout_secs: int
    avoid_cells: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, env_id: _Optional[str] = ..., subenv_id: _Optional[str] = ..., size: _Optional[_Union[Resources, _Mapping]] = ..., timeout_secs: _Optional[int] = ..., avoid_cells: _Optional[_Iterable[str]] = ...) -> None: ...

class Placement(_message.Message):
    __slots__ = ("sandbox_id", "cell_id", "cell_address", "env_id", "subenv_id", "cold", "size", "timeout_secs")
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    CELL_ID_FIELD_NUMBER: _ClassVar[int]
    CELL_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    SUBENV_ID_FIELD_NUMBER: _ClassVar[int]
    COLD_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_SECS_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    cell_id: str
    cell_address: str
    env_id: str
    subenv_id: str
    cold: bool
    size: Resources
    timeout_secs: int
    def __init__(self, sandbox_id: _Optional[str] = ..., cell_id: _Optional[str] = ..., cell_address: _Optional[str] = ..., env_id: _Optional[str] = ..., subenv_id: _Optional[str] = ..., cold: bool = ..., size: _Optional[_Union[Resources, _Mapping]] = ..., timeout_secs: _Optional[int] = ...) -> None: ...

class LocateSandboxRequest(_message.Message):
    __slots__ = ("sandbox_id",)
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    def __init__(self, sandbox_id: _Optional[str] = ...) -> None: ...

class ReleaseSandboxRequest(_message.Message):
    __slots__ = ("sandbox_id",)
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    def __init__(self, sandbox_id: _Optional[str] = ...) -> None: ...

class ReleaseSandboxResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class DrainCellRequest(_message.Message):
    __slots__ = ("cell_id",)
    CELL_ID_FIELD_NUMBER: _ClassVar[int]
    cell_id: str
    def __init__(self, cell_id: _Optional[str] = ...) -> None: ...

class DrainCellResponse(_message.Message):
    __slots__ = ("sandboxes",)
    SANDBOXES_FIELD_NUMBER: _ClassVar[int]
    sandboxes: int
    def __init__(self, sandboxes: _Optional[int] = ...) -> None: ...

class GetUsageRequest(_message.Message):
    __slots__ = ("env_id", "subenv_id", "from_unix", "to_unix")
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    SUBENV_ID_FIELD_NUMBER: _ClassVar[int]
    FROM_UNIX_FIELD_NUMBER: _ClassVar[int]
    TO_UNIX_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    subenv_id: str
    from_unix: int
    to_unix: int
    def __init__(self, env_id: _Optional[str] = ..., subenv_id: _Optional[str] = ..., from_unix: _Optional[int] = ..., to_unix: _Optional[int] = ...) -> None: ...

class Usage(_message.Message):
    __slots__ = ("cell_minutes", "cells")
    CELL_MINUTES_FIELD_NUMBER: _ClassVar[int]
    CELLS_FIELD_NUMBER: _ClassVar[int]
    cell_minutes: float
    cells: _containers.RepeatedCompositeFieldContainer[CellUsage]
    def __init__(self, cell_minutes: _Optional[float] = ..., cells: _Optional[_Iterable[_Union[CellUsage, _Mapping]]] = ...) -> None: ...

class CellUsage(_message.Message):
    __slots__ = ("cell_id", "create_called_unix_ms", "deleted_unix_ms", "cell_minutes")
    CELL_ID_FIELD_NUMBER: _ClassVar[int]
    CREATE_CALLED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    DELETED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    CELL_MINUTES_FIELD_NUMBER: _ClassVar[int]
    cell_id: str
    create_called_unix_ms: int
    deleted_unix_ms: int
    cell_minutes: float
    def __init__(self, cell_id: _Optional[str] = ..., create_called_unix_ms: _Optional[int] = ..., deleted_unix_ms: _Optional[int] = ..., cell_minutes: _Optional[float] = ...) -> None: ...

class CellReport(_message.Message):
    __slots__ = ("instance_id", "zone", "ready", "unreserved_cpu_halves", "unreserved_memory_gib", "sandbox_count", "cpu_in_use_millis", "memory_in_use_bytes", "lease_expiry_unix", "proxy_connections", "drain_state", "release_id")
    INSTANCE_ID_FIELD_NUMBER: _ClassVar[int]
    ZONE_FIELD_NUMBER: _ClassVar[int]
    READY_FIELD_NUMBER: _ClassVar[int]
    UNRESERVED_CPU_HALVES_FIELD_NUMBER: _ClassVar[int]
    UNRESERVED_MEMORY_GIB_FIELD_NUMBER: _ClassVar[int]
    SANDBOX_COUNT_FIELD_NUMBER: _ClassVar[int]
    CPU_IN_USE_MILLIS_FIELD_NUMBER: _ClassVar[int]
    MEMORY_IN_USE_BYTES_FIELD_NUMBER: _ClassVar[int]
    LEASE_EXPIRY_UNIX_FIELD_NUMBER: _ClassVar[int]
    PROXY_CONNECTIONS_FIELD_NUMBER: _ClassVar[int]
    DRAIN_STATE_FIELD_NUMBER: _ClassVar[int]
    RELEASE_ID_FIELD_NUMBER: _ClassVar[int]
    instance_id: int
    zone: str
    ready: bool
    unreserved_cpu_halves: int
    unreserved_memory_gib: int
    sandbox_count: int
    cpu_in_use_millis: int
    memory_in_use_bytes: int
    lease_expiry_unix: int
    proxy_connections: int
    drain_state: DrainState
    release_id: str
    def __init__(self, instance_id: _Optional[int] = ..., zone: _Optional[str] = ..., ready: bool = ..., unreserved_cpu_halves: _Optional[int] = ..., unreserved_memory_gib: _Optional[int] = ..., sandbox_count: _Optional[int] = ..., cpu_in_use_millis: _Optional[int] = ..., memory_in_use_bytes: _Optional[int] = ..., lease_expiry_unix: _Optional[int] = ..., proxy_connections: _Optional[int] = ..., drain_state: _Optional[_Union[DrainState, str]] = ..., release_id: _Optional[str] = ...) -> None: ...

class CellReportAck(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class PutCredentialRequest(_message.Message):
    __slots__ = ("env_id", "subenv_id", "name", "sealed")
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    SUBENV_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    SEALED_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    subenv_id: str
    name: str
    sealed: bytes
    def __init__(self, env_id: _Optional[str] = ..., subenv_id: _Optional[str] = ..., name: _Optional[str] = ..., sealed: _Optional[bytes] = ...) -> None: ...

class PutCredentialResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class FetchCredentialsRequest(_message.Message):
    __slots__ = ("instance_id", "zone", "names")
    INSTANCE_ID_FIELD_NUMBER: _ClassVar[int]
    ZONE_FIELD_NUMBER: _ClassVar[int]
    NAMES_FIELD_NUMBER: _ClassVar[int]
    instance_id: int
    zone: str
    names: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, instance_id: _Optional[int] = ..., zone: _Optional[str] = ..., names: _Optional[_Iterable[str]] = ...) -> None: ...

class SealedCredential(_message.Message):
    __slots__ = ("name", "sealed")
    NAME_FIELD_NUMBER: _ClassVar[int]
    SEALED_FIELD_NUMBER: _ClassVar[int]
    name: str
    sealed: bytes
    def __init__(self, name: _Optional[str] = ..., sealed: _Optional[bytes] = ...) -> None: ...

class FetchCredentialsResponse(_message.Message):
    __slots__ = ("credentials",)
    CREDENTIALS_FIELD_NUMBER: _ClassVar[int]
    credentials: _containers.RepeatedCompositeFieldContainer[SealedCredential]
    def __init__(self, credentials: _Optional[_Iterable[_Union[SealedCredential, _Mapping]]] = ...) -> None: ...

class PutTemplateRequest(_message.Message):
    __slots__ = ("header", "data")
    HEADER_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    header: TemplateHeader
    data: bytes
    def __init__(self, header: _Optional[_Union[TemplateHeader, _Mapping]] = ..., data: _Optional[bytes] = ...) -> None: ...

class TemplateHeader(_message.Message):
    __slots__ = ("env_id", "subenv_id", "name", "digest", "sealed_key", "plaintext_bytes")
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    SUBENV_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    DIGEST_FIELD_NUMBER: _ClassVar[int]
    SEALED_KEY_FIELD_NUMBER: _ClassVar[int]
    PLAINTEXT_BYTES_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    subenv_id: str
    name: str
    digest: str
    sealed_key: bytes
    plaintext_bytes: int
    def __init__(self, env_id: _Optional[str] = ..., subenv_id: _Optional[str] = ..., name: _Optional[str] = ..., digest: _Optional[str] = ..., sealed_key: _Optional[bytes] = ..., plaintext_bytes: _Optional[int] = ...) -> None: ...

class PutTemplateResponse(_message.Message):
    __slots__ = ("template",)
    TEMPLATE_FIELD_NUMBER: _ClassVar[int]
    template: TemplateInfo
    def __init__(self, template: _Optional[_Union[TemplateInfo, _Mapping]] = ...) -> None: ...

class GetTemplateRequest(_message.Message):
    __slots__ = ("env_id", "subenv_id", "name")
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    SUBENV_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    subenv_id: str
    name: str
    def __init__(self, env_id: _Optional[str] = ..., subenv_id: _Optional[str] = ..., name: _Optional[str] = ...) -> None: ...

class TemplateInfo(_message.Message):
    __slots__ = ("name", "digest", "ciphertext_bytes", "plaintext_bytes", "parts")
    NAME_FIELD_NUMBER: _ClassVar[int]
    DIGEST_FIELD_NUMBER: _ClassVar[int]
    CIPHERTEXT_BYTES_FIELD_NUMBER: _ClassVar[int]
    PLAINTEXT_BYTES_FIELD_NUMBER: _ClassVar[int]
    PARTS_FIELD_NUMBER: _ClassVar[int]
    name: str
    digest: str
    ciphertext_bytes: int
    plaintext_bytes: int
    parts: int
    def __init__(self, name: _Optional[str] = ..., digest: _Optional[str] = ..., ciphertext_bytes: _Optional[int] = ..., plaintext_bytes: _Optional[int] = ..., parts: _Optional[int] = ...) -> None: ...

class GetStorageRequest(_message.Message):
    __slots__ = ("instance_id", "zone")
    INSTANCE_ID_FIELD_NUMBER: _ClassVar[int]
    ZONE_FIELD_NUMBER: _ClassVar[int]
    instance_id: int
    zone: str
    def __init__(self, instance_id: _Optional[int] = ..., zone: _Optional[str] = ...) -> None: ...

class Storage(_message.Message):
    __slots__ = ("bucket", "prefix")
    BUCKET_FIELD_NUMBER: _ClassVar[int]
    PREFIX_FIELD_NUMBER: _ClassVar[int]
    bucket: str
    prefix: str
    def __init__(self, bucket: _Optional[str] = ..., prefix: _Optional[str] = ...) -> None: ...

class AcquireVolumeRequest(_message.Message):
    __slots__ = ("instance_id", "zone", "volume", "sandbox_id")
    INSTANCE_ID_FIELD_NUMBER: _ClassVar[int]
    ZONE_FIELD_NUMBER: _ClassVar[int]
    VOLUME_FIELD_NUMBER: _ClassVar[int]
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    instance_id: int
    zone: str
    volume: str
    sandbox_id: str
    def __init__(self, instance_id: _Optional[int] = ..., zone: _Optional[str] = ..., volume: _Optional[str] = ..., sandbox_id: _Optional[str] = ...) -> None: ...

class AcquireVolumeResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ReleaseVolumeRequest(_message.Message):
    __slots__ = ("instance_id", "zone", "volume", "sandbox_id")
    INSTANCE_ID_FIELD_NUMBER: _ClassVar[int]
    ZONE_FIELD_NUMBER: _ClassVar[int]
    VOLUME_FIELD_NUMBER: _ClassVar[int]
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    instance_id: int
    zone: str
    volume: str
    sandbox_id: str
    def __init__(self, instance_id: _Optional[int] = ..., zone: _Optional[str] = ..., volume: _Optional[str] = ..., sandbox_id: _Optional[str] = ...) -> None: ...

class ReleaseVolumeResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...
