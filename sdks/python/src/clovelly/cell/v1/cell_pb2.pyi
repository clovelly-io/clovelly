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
    INVALID_SANDBOX_ID: _ClassVar[ErrorReason]
    INVALID_REQUEST: _ClassVar[ErrorReason]
    NO_SUCH_SANDBOX: _ClassVar[ErrorReason]
    PERMISSION: _ClassVar[ErrorReason]
    SANDBOX_EXISTS: _ClassVar[ErrorReason]
    CAPACITY: _ClassVar[ErrorReason]
    ABOVE_POLICY_MAXIMUM: _ClassVar[ErrorReason]
    CROSSES_CELL_END: _ClassVar[ErrorReason]
    CROSSES_RELEASE_EXPIRY: _ClassVar[ErrorReason]
    DRAINING: _ClassVar[ErrorReason]
    REVOKED: _ClassVar[ErrorReason]
    SANDBOX_ENDED: _ClassVar[ErrorReason]
    NO_SUCH_FILE: _ClassVar[ErrorReason]
    RUNTIME: _ClassVar[ErrorReason]
    POLICY_REFUSED: _ClassVar[ErrorReason]
    CREDENTIAL_UNAVAILABLE: _ClassVar[ErrorReason]
    TEMPLATE_UNAVAILABLE: _ClassVar[ErrorReason]
    VOLUME_BUSY: _ClassVar[ErrorReason]
    VOLUME_UNREADABLE: _ClassVar[ErrorReason]
    VOLUME_UNAVAILABLE: _ClassVar[ErrorReason]

class ExitKind(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    EXIT_KIND_UNSPECIFIED: _ClassVar[ExitKind]
    EXIT_KIND_RUNNING: _ClassVar[ExitKind]
    EXIT_KIND_EXITED: _ClassVar[ExitKind]
    EXIT_KIND_KILLED: _ClassVar[ExitKind]
    EXIT_KIND_TIMEOUT: _ClassVar[ExitKind]
    EXIT_KIND_DRAINED: _ClassVar[ExitKind]
    EXIT_KIND_REVOKED: _ClassVar[ExitKind]
    EXIT_KIND_CELL_LOST: _ClassVar[ExitKind]
    EXIT_KIND_CELL_END: _ClassVar[ExitKind]
ERROR_REASON_UNSPECIFIED: ErrorReason
INVALID_SANDBOX_ID: ErrorReason
INVALID_REQUEST: ErrorReason
NO_SUCH_SANDBOX: ErrorReason
PERMISSION: ErrorReason
SANDBOX_EXISTS: ErrorReason
CAPACITY: ErrorReason
ABOVE_POLICY_MAXIMUM: ErrorReason
CROSSES_CELL_END: ErrorReason
CROSSES_RELEASE_EXPIRY: ErrorReason
DRAINING: ErrorReason
REVOKED: ErrorReason
SANDBOX_ENDED: ErrorReason
NO_SUCH_FILE: ErrorReason
RUNTIME: ErrorReason
POLICY_REFUSED: ErrorReason
CREDENTIAL_UNAVAILABLE: ErrorReason
TEMPLATE_UNAVAILABLE: ErrorReason
VOLUME_BUSY: ErrorReason
VOLUME_UNREADABLE: ErrorReason
VOLUME_UNAVAILABLE: ErrorReason
EXIT_KIND_UNSPECIFIED: ExitKind
EXIT_KIND_RUNNING: ExitKind
EXIT_KIND_EXITED: ExitKind
EXIT_KIND_KILLED: ExitKind
EXIT_KIND_TIMEOUT: ExitKind
EXIT_KIND_DRAINED: ExitKind
EXIT_KIND_REVOKED: ExitKind
EXIT_KIND_CELL_LOST: ExitKind
EXIT_KIND_CELL_END: ExitKind

class CreateSandboxRequest(_message.Message):
    __slots__ = ("sandbox_id", "access_key", "cpu_halves", "memory_gib", "timeout_secs", "command", "env", "template_digest", "volume", "volume_gib")
    class EnvEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    ACCESS_KEY_FIELD_NUMBER: _ClassVar[int]
    CPU_HALVES_FIELD_NUMBER: _ClassVar[int]
    MEMORY_GIB_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_SECS_FIELD_NUMBER: _ClassVar[int]
    COMMAND_FIELD_NUMBER: _ClassVar[int]
    ENV_FIELD_NUMBER: _ClassVar[int]
    TEMPLATE_DIGEST_FIELD_NUMBER: _ClassVar[int]
    VOLUME_FIELD_NUMBER: _ClassVar[int]
    VOLUME_GIB_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    access_key: bytes
    cpu_halves: int
    memory_gib: int
    timeout_secs: int
    command: _containers.RepeatedScalarFieldContainer[str]
    env: _containers.ScalarMap[str, str]
    template_digest: str
    volume: str
    volume_gib: int
    def __init__(self, sandbox_id: _Optional[str] = ..., access_key: _Optional[bytes] = ..., cpu_halves: _Optional[int] = ..., memory_gib: _Optional[int] = ..., timeout_secs: _Optional[int] = ..., command: _Optional[_Iterable[str]] = ..., env: _Optional[_Mapping[str, str]] = ..., template_digest: _Optional[str] = ..., volume: _Optional[str] = ..., volume_gib: _Optional[int] = ...) -> None: ...

class CreateSandboxResponse(_message.Message):
    __slots__ = ("started_unix_ms", "runsc_ms")
    STARTED_UNIX_MS_FIELD_NUMBER: _ClassVar[int]
    RUNSC_MS_FIELD_NUMBER: _ClassVar[int]
    started_unix_ms: int
    runsc_ms: int
    def __init__(self, started_unix_ms: _Optional[int] = ..., runsc_ms: _Optional[int] = ...) -> None: ...

class ExecRequest(_message.Message):
    __slots__ = ("start", "stdin", "stdin_eof")
    START_FIELD_NUMBER: _ClassVar[int]
    STDIN_FIELD_NUMBER: _ClassVar[int]
    STDIN_EOF_FIELD_NUMBER: _ClassVar[int]
    start: ExecStart
    stdin: bytes
    stdin_eof: bool
    def __init__(self, start: _Optional[_Union[ExecStart, _Mapping]] = ..., stdin: _Optional[bytes] = ..., stdin_eof: bool = ...) -> None: ...

class ExecStart(_message.Message):
    __slots__ = ("sandbox_id", "access_key", "args", "env", "cwd", "timeout_secs")
    class EnvEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    ACCESS_KEY_FIELD_NUMBER: _ClassVar[int]
    ARGS_FIELD_NUMBER: _ClassVar[int]
    ENV_FIELD_NUMBER: _ClassVar[int]
    CWD_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_SECS_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    access_key: bytes
    args: _containers.RepeatedScalarFieldContainer[str]
    env: _containers.ScalarMap[str, str]
    cwd: str
    timeout_secs: int
    def __init__(self, sandbox_id: _Optional[str] = ..., access_key: _Optional[bytes] = ..., args: _Optional[_Iterable[str]] = ..., env: _Optional[_Mapping[str, str]] = ..., cwd: _Optional[str] = ..., timeout_secs: _Optional[int] = ...) -> None: ...

class ExecResponse(_message.Message):
    __slots__ = ("stdout", "stderr", "exit")
    STDOUT_FIELD_NUMBER: _ClassVar[int]
    STDERR_FIELD_NUMBER: _ClassVar[int]
    EXIT_FIELD_NUMBER: _ClassVar[int]
    stdout: bytes
    stderr: bytes
    exit: ExecExit
    def __init__(self, stdout: _Optional[bytes] = ..., stderr: _Optional[bytes] = ..., exit: _Optional[_Union[ExecExit, _Mapping]] = ...) -> None: ...

class ExecExit(_message.Message):
    __slots__ = ("code", "first_exec_ms", "sandbox_ended")
    CODE_FIELD_NUMBER: _ClassVar[int]
    FIRST_EXEC_MS_FIELD_NUMBER: _ClassVar[int]
    SANDBOX_ENDED_FIELD_NUMBER: _ClassVar[int]
    code: int
    first_exec_ms: int
    sandbox_ended: ExitKind
    def __init__(self, code: _Optional[int] = ..., first_exec_ms: _Optional[int] = ..., sandbox_ended: _Optional[_Union[ExitKind, str]] = ...) -> None: ...

class ReadFileRequest(_message.Message):
    __slots__ = ("sandbox_id", "access_key", "path")
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    ACCESS_KEY_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    access_key: bytes
    path: str
    def __init__(self, sandbox_id: _Optional[str] = ..., access_key: _Optional[bytes] = ..., path: _Optional[str] = ...) -> None: ...

class FileChunk(_message.Message):
    __slots__ = ("data",)
    DATA_FIELD_NUMBER: _ClassVar[int]
    data: bytes
    def __init__(self, data: _Optional[bytes] = ...) -> None: ...

class WriteFileRequest(_message.Message):
    __slots__ = ("header", "data")
    HEADER_FIELD_NUMBER: _ClassVar[int]
    DATA_FIELD_NUMBER: _ClassVar[int]
    header: WriteFileHeader
    data: bytes
    def __init__(self, header: _Optional[_Union[WriteFileHeader, _Mapping]] = ..., data: _Optional[bytes] = ...) -> None: ...

class WriteFileHeader(_message.Message):
    __slots__ = ("sandbox_id", "access_key", "path")
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    ACCESS_KEY_FIELD_NUMBER: _ClassVar[int]
    PATH_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    access_key: bytes
    path: str
    def __init__(self, sandbox_id: _Optional[str] = ..., access_key: _Optional[bytes] = ..., path: _Optional[str] = ...) -> None: ...

class WriteFileResponse(_message.Message):
    __slots__ = ("bytes_written",)
    BYTES_WRITTEN_FIELD_NUMBER: _ClassVar[int]
    bytes_written: int
    def __init__(self, bytes_written: _Optional[int] = ...) -> None: ...

class KillRequest(_message.Message):
    __slots__ = ("sandbox_id", "access_key")
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    ACCESS_KEY_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    access_key: bytes
    def __init__(self, sandbox_id: _Optional[str] = ..., access_key: _Optional[bytes] = ...) -> None: ...

class GetReceiptRequest(_message.Message):
    __slots__ = ("sandbox_id", "access_key")
    SANDBOX_ID_FIELD_NUMBER: _ClassVar[int]
    ACCESS_KEY_FIELD_NUMBER: _ClassVar[int]
    sandbox_id: str
    access_key: bytes
    def __init__(self, sandbox_id: _Optional[str] = ..., access_key: _Optional[bytes] = ...) -> None: ...

class Receipt(_message.Message):
    __slots__ = ("json", "signature", "exit_kind", "cell_cert", "final")
    JSON_FIELD_NUMBER: _ClassVar[int]
    SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    EXIT_KIND_FIELD_NUMBER: _ClassVar[int]
    CELL_CERT_FIELD_NUMBER: _ClassVar[int]
    FINAL_FIELD_NUMBER: _ClassVar[int]
    json: bytes
    signature: bytes
    exit_kind: ExitKind
    cell_cert: bytes
    final: bool
    def __init__(self, json: _Optional[bytes] = ..., signature: _Optional[bytes] = ..., exit_kind: _Optional[_Union[ExitKind, str]] = ..., cell_cert: _Optional[bytes] = ..., final: bool = ...) -> None: ...

class DrainRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class DrainResponse(_message.Message):
    __slots__ = ("sandboxes",)
    SANDBOXES_FIELD_NUMBER: _ClassVar[int]
    sandboxes: int
    def __init__(self, sandboxes: _Optional[int] = ...) -> None: ...
