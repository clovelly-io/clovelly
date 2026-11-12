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
    QUOTA_EXCEEDED: _ClassVar[ErrorReason]
    CREDIT_EXHAUSTED: _ClassVar[ErrorReason]
    NOT_READY: _ClassVar[ErrorReason]
    SIGN_UP_CLOSED: _ClassVar[ErrorReason]
    NO_CAPACITY: _ClassVar[ErrorReason]
    UNKNOWN_REGION: _ClassVar[ErrorReason]
    BELOW_MINIMUM_TOP_UP: _ClassVar[ErrorReason]

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
QUOTA_EXCEEDED: ErrorReason
CREDIT_EXHAUSTED: ErrorReason
NOT_READY: ErrorReason
SIGN_UP_CLOSED: ErrorReason
NO_CAPACITY: ErrorReason
UNKNOWN_REGION: ErrorReason
BELOW_MINIMUM_TOP_UP: ErrorReason
DRAIN_STATE_UNSPECIFIED: DrainState
SERVING: DrainState
DRAINING: DrainState
RECYCLE: DrainState

class PutEnvironmentRequest(_message.Message):
    __slots__ = ("env_id", "verifier_url", "ca_pem", "keep_token")
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    VERIFIER_URL_FIELD_NUMBER: _ClassVar[int]
    CA_PEM_FIELD_NUMBER: _ClassVar[int]
    KEEP_TOKEN_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    verifier_url: str
    ca_pem: str
    keep_token: bool
    def __init__(self, env_id: _Optional[str] = ..., verifier_url: _Optional[str] = ..., ca_pem: _Optional[str] = ..., keep_token: bool = ...) -> None: ...

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
    __slots__ = ("env_id", "subenv_id", "machine_type", "zones", "min_warm_per_zone", "idle_window_secs", "cap_secs", "release_id", "test_metadata", "region")
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
    REGION_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    subenv_id: str
    machine_type: str
    zones: _containers.RepeatedScalarFieldContainer[str]
    min_warm_per_zone: int
    idle_window_secs: int
    cap_secs: int
    release_id: str
    test_metadata: _containers.ScalarMap[str, str]
    region: str
    def __init__(self, env_id: _Optional[str] = ..., subenv_id: _Optional[str] = ..., machine_type: _Optional[str] = ..., zones: _Optional[_Iterable[str]] = ..., min_warm_per_zone: _Optional[int] = ..., idle_window_secs: _Optional[int] = ..., cap_secs: _Optional[int] = ..., release_id: _Optional[str] = ..., test_metadata: _Optional[_Mapping[str, str]] = ..., region: _Optional[str] = ...) -> None: ...

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
    __slots__ = ("cell_id", "zone", "instance_name", "state", "address", "release_id", "create_called_unix_ms", "ready_unix_ms", "deleted_unix_ms", "cell_end_unix", "sandbox_count", "unreserved", "recycle_reason", "cpu_share")
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
    CPU_SHARE_FIELD_NUMBER: _ClassVar[int]
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
    cpu_share: int
    def __init__(self, cell_id: _Optional[str] = ..., zone: _Optional[str] = ..., instance_name: _Optional[str] = ..., state: _Optional[str] = ..., address: _Optional[str] = ..., release_id: _Optional[str] = ..., create_called_unix_ms: _Optional[int] = ..., ready_unix_ms: _Optional[int] = ..., deleted_unix_ms: _Optional[int] = ..., cell_end_unix: _Optional[int] = ..., sandbox_count: _Optional[int] = ..., unreserved: _Optional[_Union[Resources, _Mapping]] = ..., recycle_reason: _Optional[str] = ..., cpu_share: _Optional[int] = ...) -> None: ...

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
    __slots__ = ("sandbox_id", "cell_id", "cell_address", "env_id", "subenv_id", "cold", "size", "timeout_secs", "cell_name", "placement_pass")
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    CELL_ID_FIELD_NUMBER: _ClassVar[int]
    CELL_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    SUBENV_ID_FIELD_NUMBER: _ClassVar[int]
    COLD_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_SECS_FIELD_NUMBER: _ClassVar[int]
    CELL_NAME_FIELD_NUMBER: _ClassVar[int]
    PLACEMENT_PASS_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    cell_id: str
    cell_address: str
    env_id: str
    subenv_id: str
    cold: bool
    size: Resources
    timeout_secs: int
    cell_name: str
    placement_pass: str
    def __init__(self, sandbox_id: _Optional[str] = ..., cell_id: _Optional[str] = ..., cell_address: _Optional[str] = ..., env_id: _Optional[str] = ..., subenv_id: _Optional[str] = ..., cold: bool = ..., size: _Optional[_Union[Resources, _Mapping]] = ..., timeout_secs: _Optional[int] = ..., cell_name: _Optional[str] = ..., placement_pass: _Optional[str] = ...) -> None: ...

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
    __slots__ = ("instance_id", "zone", "ready", "unreserved_cpu_halves", "unreserved_memory_gib", "sandbox_count", "cpu_in_use_millis", "memory_in_use_bytes", "lease_expiry_unix", "proxy_connections", "drain_state", "release_id", "egress_bytes", "cpu_share")
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
    EGRESS_BYTES_FIELD_NUMBER: _ClassVar[int]
    CPU_SHARE_FIELD_NUMBER: _ClassVar[int]
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
    egress_bytes: int
    cpu_share: int
    def __init__(self, instance_id: _Optional[int] = ..., zone: _Optional[str] = ..., ready: bool = ..., unreserved_cpu_halves: _Optional[int] = ..., unreserved_memory_gib: _Optional[int] = ..., sandbox_count: _Optional[int] = ..., cpu_in_use_millis: _Optional[int] = ..., memory_in_use_bytes: _Optional[int] = ..., lease_expiry_unix: _Optional[int] = ..., proxy_connections: _Optional[int] = ..., drain_state: _Optional[_Union[DrainState, str]] = ..., release_id: _Optional[str] = ..., egress_bytes: _Optional[int] = ..., cpu_share: _Optional[int] = ...) -> None: ...

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

class DeleteVolumeRequest(_message.Message):
    __slots__ = ("env_id", "subenv_id", "name")
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    SUBENV_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    subenv_id: str
    name: str
    def __init__(self, env_id: _Optional[str] = ..., subenv_id: _Optional[str] = ..., name: _Optional[str] = ...) -> None: ...

class DeletedObjects(_message.Message):
    __slots__ = ("objects", "bytes")
    OBJECTS_FIELD_NUMBER: _ClassVar[int]
    BYTES_FIELD_NUMBER: _ClassVar[int]
    objects: int
    bytes: int
    def __init__(self, objects: _Optional[int] = ..., bytes: _Optional[int] = ...) -> None: ...

class Quota(_message.Message):
    __slots__ = ("env_id", "max_cells", "max_sandboxes", "max_volume_bytes")
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    MAX_CELLS_FIELD_NUMBER: _ClassVar[int]
    MAX_SANDBOXES_FIELD_NUMBER: _ClassVar[int]
    MAX_VOLUME_BYTES_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    max_cells: int
    max_sandboxes: int
    max_volume_bytes: int
    def __init__(self, env_id: _Optional[str] = ..., max_cells: _Optional[int] = ..., max_sandboxes: _Optional[int] = ..., max_volume_bytes: _Optional[int] = ...) -> None: ...

class GetQuotaRequest(_message.Message):
    __slots__ = ("env_id",)
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    def __init__(self, env_id: _Optional[str] = ...) -> None: ...

class QuotaStatus(_message.Message):
    __slots__ = ("quota", "cells", "sandboxes", "volume_bytes")
    QUOTA_FIELD_NUMBER: _ClassVar[int]
    CELLS_FIELD_NUMBER: _ClassVar[int]
    SANDBOXES_FIELD_NUMBER: _ClassVar[int]
    VOLUME_BYTES_FIELD_NUMBER: _ClassVar[int]
    quota: Quota
    cells: int
    sandboxes: int
    volume_bytes: int
    def __init__(self, quota: _Optional[_Union[Quota, _Mapping]] = ..., cells: _Optional[int] = ..., sandboxes: _Optional[int] = ..., volume_bytes: _Optional[int] = ...) -> None: ...

class DrainZoneRequest(_message.Message):
    __slots__ = ("zone",)
    ZONE_FIELD_NUMBER: _ClassVar[int]
    zone: str
    def __init__(self, zone: _Optional[str] = ...) -> None: ...

class DrainZoneResponse(_message.Message):
    __slots__ = ("cells", "replacements")
    CELLS_FIELD_NUMBER: _ClassVar[int]
    REPLACEMENTS_FIELD_NUMBER: _ClassVar[int]
    cells: int
    replacements: int
    def __init__(self, cells: _Optional[int] = ..., replacements: _Optional[int] = ...) -> None: ...

class ExportBillingRequest(_message.Message):
    __slots__ = ("env_id", "month")
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    MONTH_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    month: str
    def __init__(self, env_id: _Optional[str] = ..., month: _Optional[str] = ...) -> None: ...

class BillingExport(_message.Message):
    __slots__ = ("env_id", "month", "cells", "subenvs", "billed_ms", "total_cents")
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    MONTH_FIELD_NUMBER: _ClassVar[int]
    CELLS_FIELD_NUMBER: _ClassVar[int]
    SUBENVS_FIELD_NUMBER: _ClassVar[int]
    BILLED_MS_FIELD_NUMBER: _ClassVar[int]
    TOTAL_CENTS_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    month: str
    cells: _containers.RepeatedCompositeFieldContainer[BilledCell]
    subenvs: _containers.RepeatedCompositeFieldContainer[BilledSubenv]
    billed_ms: int
    total_cents: int
    def __init__(self, env_id: _Optional[str] = ..., month: _Optional[str] = ..., cells: _Optional[_Iterable[_Union[BilledCell, _Mapping]]] = ..., subenvs: _Optional[_Iterable[_Union[BilledSubenv, _Mapping]]] = ..., billed_ms: _Optional[int] = ..., total_cents: _Optional[int] = ...) -> None: ...

class BilledCell(_message.Message):
    __slots__ = ("subenv_id", "cell_id", "machine_type", "zone", "create_called_unix_ms", "deleted_unix_ms", "billed_ms")
    SUBENV_ID_FIELD_NUMBER: _ClassVar[int]
    CELL_ID_FIELD_NUMBER: _ClassVar[int]
    MACHINE_TYPE_FIELD_NUMBER: _ClassVar[int]
    ZONE_FIELD_NUMBER: _ClassVar[int]
    CREATE_CALLED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    DELETED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    BILLED_MS_FIELD_NUMBER: _ClassVar[int]
    subenv_id: str
    cell_id: str
    machine_type: str
    zone: str
    create_called_unix_ms: int
    deleted_unix_ms: int
    billed_ms: int
    def __init__(self, subenv_id: _Optional[str] = ..., cell_id: _Optional[str] = ..., machine_type: _Optional[str] = ..., zone: _Optional[str] = ..., create_called_unix_ms: _Optional[int] = ..., deleted_unix_ms: _Optional[int] = ..., billed_ms: _Optional[int] = ...) -> None: ...

class BilledSubenv(_message.Message):
    __slots__ = ("subenv_id", "billed_ms", "cents", "region", "egress_bytes", "egress_billed_bytes", "egress_cents")
    SUBENV_ID_FIELD_NUMBER: _ClassVar[int]
    BILLED_MS_FIELD_NUMBER: _ClassVar[int]
    CENTS_FIELD_NUMBER: _ClassVar[int]
    REGION_FIELD_NUMBER: _ClassVar[int]
    EGRESS_BYTES_FIELD_NUMBER: _ClassVar[int]
    EGRESS_BILLED_BYTES_FIELD_NUMBER: _ClassVar[int]
    EGRESS_CENTS_FIELD_NUMBER: _ClassVar[int]
    subenv_id: str
    billed_ms: int
    cents: int
    region: str
    egress_bytes: int
    egress_billed_bytes: int
    egress_cents: int
    def __init__(self, subenv_id: _Optional[str] = ..., billed_ms: _Optional[int] = ..., cents: _Optional[int] = ..., region: _Optional[str] = ..., egress_bytes: _Optional[int] = ..., egress_billed_bytes: _Optional[int] = ..., egress_cents: _Optional[int] = ...) -> None: ...

class OffboardRequest(_message.Message):
    __slots__ = ("env_id",)
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    def __init__(self, env_id: _Optional[str] = ...) -> None: ...

class OffboardResponse(_message.Message):
    __slots__ = ("env_id", "started_unix_ms", "finished_unix_ms", "cells_deleted", "objects_deleted", "bytes_deleted", "object_names_sha256", "objects_remaining", "rows_deleted")
    class RowsDeletedEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: int
        def __init__(self, key: _Optional[str] = ..., value: _Optional[int] = ...) -> None: ...
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    STARTED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    FINISHED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    CELLS_DELETED_FIELD_NUMBER: _ClassVar[int]
    OBJECTS_DELETED_FIELD_NUMBER: _ClassVar[int]
    BYTES_DELETED_FIELD_NUMBER: _ClassVar[int]
    OBJECT_NAMES_SHA256_FIELD_NUMBER: _ClassVar[int]
    OBJECTS_REMAINING_FIELD_NUMBER: _ClassVar[int]
    ROWS_DELETED_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    started_unix_ms: int
    finished_unix_ms: int
    cells_deleted: int
    objects_deleted: int
    bytes_deleted: int
    object_names_sha256: str
    objects_remaining: int
    rows_deleted: _containers.ScalarMap[str, int]
    def __init__(self, env_id: _Optional[str] = ..., started_unix_ms: _Optional[int] = ..., finished_unix_ms: _Optional[int] = ..., cells_deleted: _Optional[int] = ..., objects_deleted: _Optional[int] = ..., bytes_deleted: _Optional[int] = ..., object_names_sha256: _Optional[str] = ..., objects_remaining: _Optional[int] = ..., rows_deleted: _Optional[_Mapping[str, int]] = ...) -> None: ...

class SignInRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class SignInResponse(_message.Message):
    __slots__ = ("org_id", "role", "sign_up")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    SIGN_UP_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    role: str
    sign_up: str
    def __init__(self, org_id: _Optional[str] = ..., role: _Optional[str] = ..., sign_up: _Optional[str] = ...) -> None: ...

class SignUpRequest(_message.Message):
    __slots__ = ("org_name", "terms_sha256")
    ORG_NAME_FIELD_NUMBER: _ClassVar[int]
    TERMS_SHA256_FIELD_NUMBER: _ClassVar[int]
    org_name: str
    terms_sha256: str
    def __init__(self, org_name: _Optional[str] = ..., terms_sha256: _Optional[str] = ...) -> None: ...

class SignUpResponse(_message.Message):
    __slots__ = ("org_id", "waitlisted")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    WAITLISTED_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    waitlisted: bool
    def __init__(self, org_id: _Optional[str] = ..., waitlisted: bool = ...) -> None: ...

class GetOrgRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class EnvironmentSummary(_message.Message):
    __slots__ = ("env_id", "verifier_url", "created_unix_ms")
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    VERIFIER_URL_FIELD_NUMBER: _ClassVar[int]
    CREATED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    verifier_url: str
    created_unix_ms: int
    def __init__(self, env_id: _Optional[str] = ..., verifier_url: _Optional[str] = ..., created_unix_ms: _Optional[int] = ...) -> None: ...

class Org(_message.Message):
    __slots__ = ("org_id", "name", "role", "created_unix_ms", "environments", "granted_envs", "card_on_file", "paused", "services")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    CREATED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENTS_FIELD_NUMBER: _ClassVar[int]
    GRANTED_ENVS_FIELD_NUMBER: _ClassVar[int]
    CARD_ON_FILE_FIELD_NUMBER: _ClassVar[int]
    PAUSED_FIELD_NUMBER: _ClassVar[int]
    SERVICES_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    name: str
    role: str
    created_unix_ms: int
    environments: _containers.RepeatedCompositeFieldContainer[EnvironmentSummary]
    granted_envs: _containers.RepeatedScalarFieldContainer[str]
    card_on_file: bool
    paused: str
    services: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, org_id: _Optional[str] = ..., name: _Optional[str] = ..., role: _Optional[str] = ..., created_unix_ms: _Optional[int] = ..., environments: _Optional[_Iterable[_Union[EnvironmentSummary, _Mapping]]] = ..., granted_envs: _Optional[_Iterable[str]] = ..., card_on_file: bool = ..., paused: _Optional[str] = ..., services: _Optional[_Iterable[str]] = ...) -> None: ...

class SetServiceAccessRequest(_message.Message):
    __slots__ = ("service", "allowed")
    SERVICE_FIELD_NUMBER: _ClassVar[int]
    ALLOWED_FIELD_NUMBER: _ClassVar[int]
    service: str
    allowed: bool
    def __init__(self, service: _Optional[str] = ..., allowed: bool = ...) -> None: ...

class DeleteOrgRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class DeleteOrgResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ListAuditRequest(_message.Message):
    __slots__ = ("limit",)
    LIMIT_FIELD_NUMBER: _ClassVar[int]
    limit: int
    def __init__(self, limit: _Optional[int] = ...) -> None: ...

class AuditEvent(_message.Message):
    __slots__ = ("at_unix_ms", "actor", "action", "target", "detail_json")
    AT_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    ACTOR_FIELD_NUMBER: _ClassVar[int]
    ACTION_FIELD_NUMBER: _ClassVar[int]
    TARGET_FIELD_NUMBER: _ClassVar[int]
    DETAIL_JSON_FIELD_NUMBER: _ClassVar[int]
    at_unix_ms: int
    actor: str
    action: str
    target: str
    detail_json: str
    def __init__(self, at_unix_ms: _Optional[int] = ..., actor: _Optional[str] = ..., action: _Optional[str] = ..., target: _Optional[str] = ..., detail_json: _Optional[str] = ...) -> None: ...

class ListAuditResponse(_message.Message):
    __slots__ = ("events",)
    EVENTS_FIELD_NUMBER: _ClassVar[int]
    events: _containers.RepeatedCompositeFieldContainer[AuditEvent]
    def __init__(self, events: _Optional[_Iterable[_Union[AuditEvent, _Mapping]]] = ...) -> None: ...

class CheckVerifierRequest(_message.Message):
    __slots__ = ("verifier_url", "env_id")
    VERIFIER_URL_FIELD_NUMBER: _ClassVar[int]
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    verifier_url: str
    env_id: str
    def __init__(self, verifier_url: _Optional[str] = ..., env_id: _Optional[str] = ...) -> None: ...

class CheckVerifierResponse(_message.Message):
    __slots__ = ("ok", "problem", "ca_pem")
    OK_FIELD_NUMBER: _ClassVar[int]
    PROBLEM_FIELD_NUMBER: _ClassVar[int]
    CA_PEM_FIELD_NUMBER: _ClassVar[int]
    ok: bool
    problem: str
    ca_pem: str
    def __init__(self, ok: bool = ..., problem: _Optional[str] = ..., ca_pem: _Optional[str] = ...) -> None: ...

class CreateEnvironmentRequest(_message.Message):
    __slots__ = ("env_id", "verifier_url")
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    VERIFIER_URL_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    verifier_url: str
    def __init__(self, env_id: _Optional[str] = ..., verifier_url: _Optional[str] = ...) -> None: ...

class CreateEnvironmentResponse(_message.Message):
    __slots__ = ("env_id", "key", "key_plaintext")
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    KEY_FIELD_NUMBER: _ClassVar[int]
    KEY_PLAINTEXT_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    key: ApiKey
    key_plaintext: str
    def __init__(self, env_id: _Optional[str] = ..., key: _Optional[_Union[ApiKey, _Mapping]] = ..., key_plaintext: _Optional[str] = ...) -> None: ...

class EnvRequest(_message.Message):
    __slots__ = ("env_id",)
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    def __init__(self, env_id: _Optional[str] = ...) -> None: ...

class SubenvironmentRow(_message.Message):
    __slots__ = ("subenv", "pool")
    SUBENV_FIELD_NUMBER: _ClassVar[int]
    POOL_FIELD_NUMBER: _ClassVar[int]
    subenv: Subenvironment
    pool: Pool
    def __init__(self, subenv: _Optional[_Union[Subenvironment, _Mapping]] = ..., pool: _Optional[_Union[Pool, _Mapping]] = ...) -> None: ...

class ListSubenvironmentsResponse(_message.Message):
    __slots__ = ("subenvs",)
    SUBENVS_FIELD_NUMBER: _ClassVar[int]
    subenvs: _containers.RepeatedCompositeFieldContainer[SubenvironmentRow]
    def __init__(self, subenvs: _Optional[_Iterable[_Union[SubenvironmentRow, _Mapping]]] = ...) -> None: ...

class PlacementRow(_message.Message):
    __slots__ = ("sandbox_id", "subenv_id", "cell_id", "size", "placed_unix_ms", "expires_unix_ms", "released_unix_ms", "cold")
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    SUBENV_ID_FIELD_NUMBER: _ClassVar[int]
    CELL_ID_FIELD_NUMBER: _ClassVar[int]
    SIZE_FIELD_NUMBER: _ClassVar[int]
    PLACED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    RELEASED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    COLD_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    subenv_id: str
    cell_id: str
    size: Resources
    placed_unix_ms: int
    expires_unix_ms: int
    released_unix_ms: int
    cold: bool
    def __init__(self, sandbox_id: _Optional[str] = ..., subenv_id: _Optional[str] = ..., cell_id: _Optional[str] = ..., size: _Optional[_Union[Resources, _Mapping]] = ..., placed_unix_ms: _Optional[int] = ..., expires_unix_ms: _Optional[int] = ..., released_unix_ms: _Optional[int] = ..., cold: bool = ...) -> None: ...

class ListPlacementsResponse(_message.Message):
    __slots__ = ("placements",)
    PLACEMENTS_FIELD_NUMBER: _ClassVar[int]
    placements: _containers.RepeatedCompositeFieldContainer[PlacementRow]
    def __init__(self, placements: _Optional[_Iterable[_Union[PlacementRow, _Mapping]]] = ...) -> None: ...

class CellRow(_message.Message):
    __slots__ = ("cell_id", "subenv_id", "state", "zone", "release_id", "sandbox_count", "cpu_in_use_millis", "memory_in_use_bytes", "lease_expiry_unix", "drain_state", "reported_unix_ms", "cpu_share")
    CELL_ID_FIELD_NUMBER: _ClassVar[int]
    SUBENV_ID_FIELD_NUMBER: _ClassVar[int]
    STATE_FIELD_NUMBER: _ClassVar[int]
    ZONE_FIELD_NUMBER: _ClassVar[int]
    RELEASE_ID_FIELD_NUMBER: _ClassVar[int]
    SANDBOX_COUNT_FIELD_NUMBER: _ClassVar[int]
    CPU_IN_USE_MILLIS_FIELD_NUMBER: _ClassVar[int]
    MEMORY_IN_USE_BYTES_FIELD_NUMBER: _ClassVar[int]
    LEASE_EXPIRY_UNIX_FIELD_NUMBER: _ClassVar[int]
    DRAIN_STATE_FIELD_NUMBER: _ClassVar[int]
    REPORTED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    CPU_SHARE_FIELD_NUMBER: _ClassVar[int]
    cell_id: str
    subenv_id: str
    state: str
    zone: str
    release_id: str
    sandbox_count: int
    cpu_in_use_millis: int
    memory_in_use_bytes: int
    lease_expiry_unix: int
    drain_state: str
    reported_unix_ms: int
    cpu_share: int
    def __init__(self, cell_id: _Optional[str] = ..., subenv_id: _Optional[str] = ..., state: _Optional[str] = ..., zone: _Optional[str] = ..., release_id: _Optional[str] = ..., sandbox_count: _Optional[int] = ..., cpu_in_use_millis: _Optional[int] = ..., memory_in_use_bytes: _Optional[int] = ..., lease_expiry_unix: _Optional[int] = ..., drain_state: _Optional[str] = ..., reported_unix_ms: _Optional[int] = ..., cpu_share: _Optional[int] = ...) -> None: ...

class ListCellsResponse(_message.Message):
    __slots__ = ("cells",)
    CELLS_FIELD_NUMBER: _ClassVar[int]
    cells: _containers.RepeatedCompositeFieldContainer[CellRow]
    def __init__(self, cells: _Optional[_Iterable[_Union[CellRow, _Mapping]]] = ...) -> None: ...

class TemplateRow(_message.Message):
    __slots__ = ("subenv_id", "template", "uploaded_unix_ms")
    SUBENV_ID_FIELD_NUMBER: _ClassVar[int]
    TEMPLATE_FIELD_NUMBER: _ClassVar[int]
    UPLOADED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    subenv_id: str
    template: TemplateInfo
    uploaded_unix_ms: int
    def __init__(self, subenv_id: _Optional[str] = ..., template: _Optional[_Union[TemplateInfo, _Mapping]] = ..., uploaded_unix_ms: _Optional[int] = ...) -> None: ...

class ListTemplatesResponse(_message.Message):
    __slots__ = ("templates",)
    TEMPLATES_FIELD_NUMBER: _ClassVar[int]
    templates: _containers.RepeatedCompositeFieldContainer[TemplateRow]
    def __init__(self, templates: _Optional[_Iterable[_Union[TemplateRow, _Mapping]]] = ...) -> None: ...

class GetDailyUsageRequest(_message.Message):
    __slots__ = ("env_id", "month")
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    MONTH_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    month: str
    def __init__(self, env_id: _Optional[str] = ..., month: _Optional[str] = ...) -> None: ...

class DailyUsageRow(_message.Message):
    __slots__ = ("day", "subenv_id", "cell_minutes", "region", "egress_bytes", "egress_billed_bytes")
    DAY_FIELD_NUMBER: _ClassVar[int]
    SUBENV_ID_FIELD_NUMBER: _ClassVar[int]
    CELL_MINUTES_FIELD_NUMBER: _ClassVar[int]
    REGION_FIELD_NUMBER: _ClassVar[int]
    EGRESS_BYTES_FIELD_NUMBER: _ClassVar[int]
    EGRESS_BILLED_BYTES_FIELD_NUMBER: _ClassVar[int]
    day: str
    subenv_id: str
    cell_minutes: float
    region: str
    egress_bytes: int
    egress_billed_bytes: int
    def __init__(self, day: _Optional[str] = ..., subenv_id: _Optional[str] = ..., cell_minutes: _Optional[float] = ..., region: _Optional[str] = ..., egress_bytes: _Optional[int] = ..., egress_billed_bytes: _Optional[int] = ...) -> None: ...

class DailySandboxes(_message.Message):
    __slots__ = ("day", "peak_concurrent")
    DAY_FIELD_NUMBER: _ClassVar[int]
    PEAK_CONCURRENT_FIELD_NUMBER: _ClassVar[int]
    day: str
    peak_concurrent: int
    def __init__(self, day: _Optional[str] = ..., peak_concurrent: _Optional[int] = ...) -> None: ...

class DailyUsage(_message.Message):
    __slots__ = ("rows", "sandboxes", "total_cents", "cell_cents", "egress_cents")
    ROWS_FIELD_NUMBER: _ClassVar[int]
    SANDBOXES_FIELD_NUMBER: _ClassVar[int]
    TOTAL_CENTS_FIELD_NUMBER: _ClassVar[int]
    CELL_CENTS_FIELD_NUMBER: _ClassVar[int]
    EGRESS_CENTS_FIELD_NUMBER: _ClassVar[int]
    rows: _containers.RepeatedCompositeFieldContainer[DailyUsageRow]
    sandboxes: _containers.RepeatedCompositeFieldContainer[DailySandboxes]
    total_cents: int
    cell_cents: int
    egress_cents: int
    def __init__(self, rows: _Optional[_Iterable[_Union[DailyUsageRow, _Mapping]]] = ..., sandboxes: _Optional[_Iterable[_Union[DailySandboxes, _Mapping]]] = ..., total_cents: _Optional[int] = ..., cell_cents: _Optional[int] = ..., egress_cents: _Optional[int] = ...) -> None: ...

class ApiKey(_message.Message):
    __slots__ = ("key_id", "env_id", "name", "role", "prefix", "created_by", "created_unix_ms", "revoked_unix_ms", "last_used_unix_ms")
    KEY_ID_FIELD_NUMBER: _ClassVar[int]
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    PREFIX_FIELD_NUMBER: _ClassVar[int]
    CREATED_BY_FIELD_NUMBER: _ClassVar[int]
    CREATED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    REVOKED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    LAST_USED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    key_id: str
    env_id: str
    name: str
    role: str
    prefix: str
    created_by: str
    created_unix_ms: int
    revoked_unix_ms: int
    last_used_unix_ms: int
    def __init__(self, key_id: _Optional[str] = ..., env_id: _Optional[str] = ..., name: _Optional[str] = ..., role: _Optional[str] = ..., prefix: _Optional[str] = ..., created_by: _Optional[str] = ..., created_unix_ms: _Optional[int] = ..., revoked_unix_ms: _Optional[int] = ..., last_used_unix_ms: _Optional[int] = ...) -> None: ...

class ListKeysResponse(_message.Message):
    __slots__ = ("keys",)
    KEYS_FIELD_NUMBER: _ClassVar[int]
    keys: _containers.RepeatedCompositeFieldContainer[ApiKey]
    def __init__(self, keys: _Optional[_Iterable[_Union[ApiKey, _Mapping]]] = ...) -> None: ...

class CreateKeyRequest(_message.Message):
    __slots__ = ("env_id", "name", "role")
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    name: str
    role: str
    def __init__(self, env_id: _Optional[str] = ..., name: _Optional[str] = ..., role: _Optional[str] = ...) -> None: ...

class CreateKeyResponse(_message.Message):
    __slots__ = ("key", "plaintext")
    KEY_FIELD_NUMBER: _ClassVar[int]
    PLAINTEXT_FIELD_NUMBER: _ClassVar[int]
    key: ApiKey
    plaintext: str
    def __init__(self, key: _Optional[_Union[ApiKey, _Mapping]] = ..., plaintext: _Optional[str] = ...) -> None: ...

class RevokeKeyRequest(_message.Message):
    __slots__ = ("env_id", "key_id")
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    KEY_ID_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    key_id: str
    def __init__(self, env_id: _Optional[str] = ..., key_id: _Optional[str] = ...) -> None: ...

class RevokeKeyResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class Member(_message.Message):
    __slots__ = ("user_id", "email", "role", "granted_envs", "joined_unix_ms")
    USER_ID_FIELD_NUMBER: _ClassVar[int]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    GRANTED_ENVS_FIELD_NUMBER: _ClassVar[int]
    JOINED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    user_id: str
    email: str
    role: str
    granted_envs: _containers.RepeatedScalarFieldContainer[str]
    joined_unix_ms: int
    def __init__(self, user_id: _Optional[str] = ..., email: _Optional[str] = ..., role: _Optional[str] = ..., granted_envs: _Optional[_Iterable[str]] = ..., joined_unix_ms: _Optional[int] = ...) -> None: ...

class Invitation(_message.Message):
    __slots__ = ("invitation_id", "email", "role", "granted_envs", "sent_unix_ms")
    INVITATION_ID_FIELD_NUMBER: _ClassVar[int]
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    GRANTED_ENVS_FIELD_NUMBER: _ClassVar[int]
    SENT_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    invitation_id: str
    email: str
    role: str
    granted_envs: _containers.RepeatedScalarFieldContainer[str]
    sent_unix_ms: int
    def __init__(self, invitation_id: _Optional[str] = ..., email: _Optional[str] = ..., role: _Optional[str] = ..., granted_envs: _Optional[_Iterable[str]] = ..., sent_unix_ms: _Optional[int] = ...) -> None: ...

class ListMembersRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ListMembersResponse(_message.Message):
    __slots__ = ("members", "invitations")
    MEMBERS_FIELD_NUMBER: _ClassVar[int]
    INVITATIONS_FIELD_NUMBER: _ClassVar[int]
    members: _containers.RepeatedCompositeFieldContainer[Member]
    invitations: _containers.RepeatedCompositeFieldContainer[Invitation]
    def __init__(self, members: _Optional[_Iterable[_Union[Member, _Mapping]]] = ..., invitations: _Optional[_Iterable[_Union[Invitation, _Mapping]]] = ...) -> None: ...

class InviteMemberRequest(_message.Message):
    __slots__ = ("email", "role", "granted_envs")
    EMAIL_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    GRANTED_ENVS_FIELD_NUMBER: _ClassVar[int]
    email: str
    role: str
    granted_envs: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, email: _Optional[str] = ..., role: _Optional[str] = ..., granted_envs: _Optional[_Iterable[str]] = ...) -> None: ...

class RevokeInvitationRequest(_message.Message):
    __slots__ = ("invitation_id",)
    INVITATION_ID_FIELD_NUMBER: _ClassVar[int]
    invitation_id: str
    def __init__(self, invitation_id: _Optional[str] = ...) -> None: ...

class RevokeInvitationResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class SetMemberRequest(_message.Message):
    __slots__ = ("user_id", "role", "granted_envs")
    USER_ID_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    GRANTED_ENVS_FIELD_NUMBER: _ClassVar[int]
    user_id: str
    role: str
    granted_envs: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, user_id: _Optional[str] = ..., role: _Optional[str] = ..., granted_envs: _Optional[_Iterable[str]] = ...) -> None: ...

class RemoveMemberRequest(_message.Message):
    __slots__ = ("user_id",)
    USER_ID_FIELD_NUMBER: _ClassVar[int]
    user_id: str
    def __init__(self, user_id: _Optional[str] = ...) -> None: ...

class RemoveMemberResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class CreditGrant(_message.Message):
    __slots__ = ("kind", "amount_cents", "left_cents", "granted_unix_ms", "expires_unix_ms")
    KIND_FIELD_NUMBER: _ClassVar[int]
    AMOUNT_CENTS_FIELD_NUMBER: _ClassVar[int]
    LEFT_CENTS_FIELD_NUMBER: _ClassVar[int]
    GRANTED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    EXPIRES_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    kind: str
    amount_cents: int
    left_cents: int
    granted_unix_ms: int
    expires_unix_ms: int
    def __init__(self, kind: _Optional[str] = ..., amount_cents: _Optional[int] = ..., left_cents: _Optional[int] = ..., granted_unix_ms: _Optional[int] = ..., expires_unix_ms: _Optional[int] = ...) -> None: ...

class Charge(_message.Message):
    __slots__ = ("kind", "amount_cents", "status", "pay_url", "created_unix_ms", "failed_unix_ms", "paid_unix_ms")
    KIND_FIELD_NUMBER: _ClassVar[int]
    AMOUNT_CENTS_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    PAY_URL_FIELD_NUMBER: _ClassVar[int]
    CREATED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    FAILED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    PAID_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    kind: str
    amount_cents: int
    status: str
    pay_url: str
    created_unix_ms: int
    failed_unix_ms: int
    paid_unix_ms: int
    def __init__(self, kind: _Optional[str] = ..., amount_cents: _Optional[int] = ..., status: _Optional[str] = ..., pay_url: _Optional[str] = ..., created_unix_ms: _Optional[int] = ..., failed_unix_ms: _Optional[int] = ..., paid_unix_ms: _Optional[int] = ...) -> None: ...

class Billing(_message.Message):
    __slots__ = ("balance_cents", "balance_unix_ms", "credits", "charges", "card_on_file", "card_summary", "period_start_unix_ms", "period_end_unix_ms", "environment_fee_cents", "low_balance_cents", "recharge_cents", "paused", "top_up_min_cents")
    BALANCE_CENTS_FIELD_NUMBER: _ClassVar[int]
    BALANCE_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    CREDITS_FIELD_NUMBER: _ClassVar[int]
    CHARGES_FIELD_NUMBER: _ClassVar[int]
    CARD_ON_FILE_FIELD_NUMBER: _ClassVar[int]
    CARD_SUMMARY_FIELD_NUMBER: _ClassVar[int]
    PERIOD_START_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    PERIOD_END_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    ENVIRONMENT_FEE_CENTS_FIELD_NUMBER: _ClassVar[int]
    LOW_BALANCE_CENTS_FIELD_NUMBER: _ClassVar[int]
    RECHARGE_CENTS_FIELD_NUMBER: _ClassVar[int]
    PAUSED_FIELD_NUMBER: _ClassVar[int]
    TOP_UP_MIN_CENTS_FIELD_NUMBER: _ClassVar[int]
    balance_cents: int
    balance_unix_ms: int
    credits: _containers.RepeatedCompositeFieldContainer[CreditGrant]
    charges: _containers.RepeatedCompositeFieldContainer[Charge]
    card_on_file: bool
    card_summary: str
    period_start_unix_ms: int
    period_end_unix_ms: int
    environment_fee_cents: int
    low_balance_cents: int
    recharge_cents: int
    paused: str
    top_up_min_cents: int
    def __init__(self, balance_cents: _Optional[int] = ..., balance_unix_ms: _Optional[int] = ..., credits: _Optional[_Iterable[_Union[CreditGrant, _Mapping]]] = ..., charges: _Optional[_Iterable[_Union[Charge, _Mapping]]] = ..., card_on_file: bool = ..., card_summary: _Optional[str] = ..., period_start_unix_ms: _Optional[int] = ..., period_end_unix_ms: _Optional[int] = ..., environment_fee_cents: _Optional[int] = ..., low_balance_cents: _Optional[int] = ..., recharge_cents: _Optional[int] = ..., paused: _Optional[str] = ..., top_up_min_cents: _Optional[int] = ...) -> None: ...

class GetBillingRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class CardSetupRequest(_message.Message):
    __slots__ = ("return_url",)
    RETURN_URL_FIELD_NUMBER: _ClassVar[int]
    return_url: str
    def __init__(self, return_url: _Optional[str] = ...) -> None: ...

class HostedPage(_message.Message):
    __slots__ = ("url",)
    URL_FIELD_NUMBER: _ClassVar[int]
    url: str
    def __init__(self, url: _Optional[str] = ...) -> None: ...

class ConfirmCardRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class BuyCreditRequest(_message.Message):
    __slots__ = ("cents", "request_id")
    CENTS_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    cents: int
    request_id: str
    def __init__(self, cents: _Optional[int] = ..., request_id: _Optional[str] = ...) -> None: ...

class SetAutoRechargeRequest(_message.Message):
    __slots__ = ("low_balance_cents", "recharge_cents")
    LOW_BALANCE_CENTS_FIELD_NUMBER: _ClassVar[int]
    RECHARGE_CENTS_FIELD_NUMBER: _ClassVar[int]
    low_balance_cents: int
    recharge_cents: int
    def __init__(self, low_balance_cents: _Optional[int] = ..., recharge_cents: _Optional[int] = ...) -> None: ...

class StripeWebhookRequest(_message.Message):
    __slots__ = ("payload", "signature")
    PAYLOAD_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    payload: bytes
    signature: str
    def __init__(self, payload: _Optional[bytes] = ..., signature: _Optional[str] = ...) -> None: ...

class StripeWebhookResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class GetBalanceRequest(_message.Message):
    __slots__ = ("org_id",)
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    def __init__(self, org_id: _Optional[str] = ...) -> None: ...

class Balance(_message.Message):
    __slots__ = ("org_id", "balance_cents", "paused")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    BALANCE_CENTS_FIELD_NUMBER: _ClassVar[int]
    PAUSED_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    balance_cents: int
    paused: str
    def __init__(self, org_id: _Optional[str] = ..., balance_cents: _Optional[int] = ..., paused: _Optional[str] = ...) -> None: ...

class DebitRequest(_message.Message):
    __slots__ = ("org_id", "cents", "idempotency_key", "memo")
    ORG_ID_FIELD_NUMBER: _ClassVar[int]
    CENTS_FIELD_NUMBER: _ClassVar[int]
    IDEMPOTENCY_KEY_FIELD_NUMBER: _ClassVar[int]
    MEMO_FIELD_NUMBER: _ClassVar[int]
    org_id: str
    cents: int
    idempotency_key: str
    memo: str
    def __init__(self, org_id: _Optional[str] = ..., cents: _Optional[int] = ..., idempotency_key: _Optional[str] = ..., memo: _Optional[str] = ...) -> None: ...

class DebitResponse(_message.Message):
    __slots__ = ("debited", "balance_cents")
    DEBITED_FIELD_NUMBER: _ClassVar[int]
    BALANCE_CENTS_FIELD_NUMBER: _ClassVar[int]
    debited: bool
    balance_cents: int
    def __init__(self, debited: bool = ..., balance_cents: _Optional[int] = ...) -> None: ...

class GetEnvironmentUsageRequest(_message.Message):
    __slots__ = ("env_id", "day")
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    DAY_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    day: str
    def __init__(self, env_id: _Optional[str] = ..., day: _Optional[str] = ...) -> None: ...

class EnvironmentUsage(_message.Message):
    __slots__ = ("env_id", "day", "cents")
    ENV_ID_FIELD_NUMBER: _ClassVar[int]
    DAY_FIELD_NUMBER: _ClassVar[int]
    CENTS_FIELD_NUMBER: _ClassVar[int]
    env_id: str
    day: str
    cents: int
    def __init__(self, env_id: _Optional[str] = ..., day: _Optional[str] = ..., cents: _Optional[int] = ...) -> None: ...
