// The protocol: hand-written TypeScript mirrors of the messages the SDK uses, and the
// services loaded at runtime from the package's own copy of the protos (proto/, copied
// from the repository's proto/ by `npm run protos`). The protos' comments are the
// contract; field comments here only note what the TypeScript shape adds.
//
// Shapes follow the loader options below: camelCase fields, uint64 as number (values stay
// below 2^53), enums as their names, bytes as Buffer, and every non-oneof field present
// on decode (`defaults: true`). A oneof is encoded with exactly one member set and decodes
// with `msg` naming the member that is set.
import { fileURLToPath } from "node:url";
import * as protoLoader from "@grpc/proto-loader";

/** A oneof as it is sent: exactly one member of `T` set. */
export type OneOf<T> = {
  [K in keyof T]: { [P in K]: T[P] } & { [P in Exclude<keyof T, K>]?: never };
}[keyof T];

/** A oneof as it is received: the member that is set, and `msg` naming it. */
export type Decoded<T> = { [K in keyof T]: { msg: K } & { [P in K]: T[P] } }[keyof T];

type Rpc<Req, Res, ReqOut = Req, ResOut = Res> = protoLoader.MethodDefinition<Req, Res, ReqOut, ResOut>;

// Services are type aliases, not interfaces, so they also satisfy grpc-js's index-signature
// `ServiceDefinition` (the test servers pass them to `Server.addService`).

// clovelly.cell.v1

/** `ExitKind` names as they cross the wire, mapped to the SDK's lowercase exit kinds. */
export const EXIT_KINDS = {
  EXIT_KIND_UNSPECIFIED: undefined,
  EXIT_KIND_RUNNING: "running",
  EXIT_KIND_EXITED: "exited",
  EXIT_KIND_KILLED: "killed",
  EXIT_KIND_TIMEOUT: "timeout",
  EXIT_KIND_DRAINED: "drained",
  EXIT_KIND_REVOKED: "revoked",
  EXIT_KIND_CELL_LOST: "cell_lost",
  EXIT_KIND_CELL_END: "cell_end",
} as const;

export type WireExitKind = keyof typeof EXIT_KINDS;

export interface CreateSandboxRequest {
  sandboxId: string;
  accessKey: Buffer;
  cpuHalves: number;
  memoryGib: number;
  timeoutSecs: number;
  command: readonly string[];
  env: Readonly<Record<string, string>>;
  /** Empty: the base bundle. */
  templateDigest: string;
  /** Empty: no volume. */
  volume: string;
  /** 0: the default (1 GiB) when the volume is created. */
  volumeGib: number;
}

export interface CreateSandboxResponse {
  startedUnixMs: number;
  runscMs: number;
}

export interface ExecStart {
  sandboxId: string;
  accessKey: Buffer;
  args: readonly string[];
  env: Readonly<Record<string, string>>;
  cwd: string;
  timeoutSecs: number;
}

/** `ExecRequest.msg`. */
export interface ExecRequestMsg {
  start: ExecStart;
  stdin: Buffer;
  stdinEof: boolean;
}
export type ExecRequest = OneOf<ExecRequestMsg>;

export interface ExecExit {
  code: number;
  firstExecMs: number;
  sandboxEnded: WireExitKind;
}

/** `ExecResponse.msg`. */
export interface ExecResponseMsg {
  stdout: Buffer;
  stderr: Buffer;
  exit: ExecExit;
}
export type ExecResponse = OneOf<ExecResponseMsg>;

/** The fields every per-sandbox call carries: `KillRequest` and `GetReceiptRequest`. */
export interface SandboxRequest {
  sandboxId: string;
  accessKey: Buffer;
}

export interface ReadFileRequest extends SandboxRequest {
  path: string;
}

export interface FileChunk {
  data: Buffer;
}

/** Same fields as `ReadFileRequest`. */
export type WriteFileHeader = ReadFileRequest;

/** `WriteFileRequest.msg`. */
export interface WriteFileRequestMsg {
  header: WriteFileHeader;
  data: Buffer;
}
export type WriteFileRequest = OneOf<WriteFileRequestMsg>;

export interface WriteFileResponse {
  bytesWritten: number;
}

export interface Receipt {
  json: Buffer;
  signature: Buffer;
  exitKind: WireExitKind;
  cellCert: Buffer;
  final: boolean;
}

export type CellService = {
  CreateSandbox: Rpc<CreateSandboxRequest, CreateSandboxResponse>;
  Exec: Rpc<ExecRequest, ExecResponse, Decoded<ExecRequestMsg>, Decoded<ExecResponseMsg>>;
  ReadFile: Rpc<ReadFileRequest, FileChunk>;
  WriteFile: Rpc<WriteFileRequest, WriteFileResponse, Decoded<WriteFileRequestMsg>>;
  Kill: Rpc<SandboxRequest, Receipt>;
  GetReceipt: Rpc<SandboxRequest, Receipt>;
};

// clovelly.control.v1

export interface Resources {
  cpuHalves: number;
  memoryGib: number;
}

export interface PlaceSandboxRequest {
  envId: string;
  subenvId: string;
  size: Resources;
  timeoutSecs: number;
  avoidCells: readonly string[];
}

export interface Placement {
  sandboxId: string;
  cellId: string;
  cellAddress: string;
  envId: string;
  subenvId: string;
  cold: boolean;
  /** Null when the control plane left it unset. */
  size: Resources | null;
  timeoutSecs: number;
}

/** A sub-environment's pool; `region` and the customer's settings, `zones` read only. */
export interface Pool {
  envId: string;
  subenvId: string;
  machineType: string;
  zones: readonly string[];
  minWarmPerZone: number;
  idleWindowSecs: number;
  capSecs: number;
  releaseId: string;
  testMetadata: Record<string, string>;
  region: string;
}

/** `LocateSandboxRequest` and `ReleaseSandboxRequest`. */
export interface SandboxIdRequest {
  sandboxId: string;
}

/** `ReleaseSandboxResponse`. */
export type Empty = Record<string, never>;

export interface PutCredentialRequest {
  envId: string;
  subenvId: string;
  name: string;
  sealed: Buffer;
}

export interface TemplateHeader {
  envId: string;
  subenvId: string;
  name: string;
  digest: string;
  sealedKey: Buffer;
  plaintextBytes: number;
}

/** `PutTemplateRequest.msg`. */
export interface PutTemplateRequestMsg {
  header: TemplateHeader;
  data: Buffer;
}
export type PutTemplateRequest = OneOf<PutTemplateRequestMsg>;

export interface TemplateInfo {
  name: string;
  digest: string;
  ciphertextBytes: number;
  plaintextBytes: number;
  parts: number;
}

export interface PutTemplateResponse {
  /** Null when the control plane left it unset. */
  template: TemplateInfo | null;
}

export interface GetTemplateRequest {
  envId: string;
  subenvId: string;
  name: string;
}

export type ControlService = {
  PlaceSandbox: Rpc<PlaceSandboxRequest, Placement>;
  PutPool: Rpc<Partial<Pool>, Pool>;
  LocateSandbox: Rpc<SandboxIdRequest, Placement>;
  ReleaseSandbox: Rpc<SandboxIdRequest, Empty>;
  PutCredential: Rpc<PutCredentialRequest, Empty>;
  PutTemplate: Rpc<PutTemplateRequest, PutTemplateResponse, Decoded<PutTemplateRequestMsg>>;
  GetTemplate: Rpc<GetTemplateRequest, TemplateInfo>;
};

// clovelly.verifier.v1

export interface SealCredentialRequest {
  envId: string;
  subenvId: string;
  name: string;
  adapter: string;
  destination: string;
  secret: Buffer;
}

export interface SealCredentialResponse {
  sealed: Buffer;
}

export interface SealTemplateKeyRequest {
  envId: string;
  subenvId: string;
  digest: string;
}

export interface SealTemplateKeyResponse {
  key: Buffer;
  sealedKey: Buffer;
}

export interface ListReceiptsRequest {
  envId: string;
  subenvId: string;
  sandboxIds: readonly string[];
}

export interface LoggedReceipt {
  receipt: Buffer;
  signature: Buffer;
  cellCert: Buffer;
  final: boolean;
  receivedUnixMs: number;
  records: number;
  finals: number;
}

export interface ListReceiptsResponse {
  receipts: LoggedReceipt[];
}

export interface GetEgressLogRequest {
  envId: string;
  sandboxId: string;
}

export interface GetEgressLogResponse {
  lines: readonly string[];
  sha256: string;
}

export type VerifierService = {
  SealCredential: Rpc<SealCredentialRequest, SealCredentialResponse>;
  SealTemplateKey: Rpc<SealTemplateKeyRequest, SealTemplateKeyResponse>;
  ListReceipts: Rpc<ListReceiptsRequest, ListReceiptsResponse>;
  GetEgressLog: Rpc<GetEgressLogRequest, GetEgressLogResponse>;
};

// grpc.health.v1

export interface HealthCheckRequest {
  service: string;
}

export interface HealthCheckResponse {
  status: "UNKNOWN" | "SERVING" | "NOT_SERVING" | "SERVICE_UNKNOWN";
}

export type HealthService = {
  Check: Rpc<HealthCheckRequest, HealthCheckResponse>;
};

// Loading

const protoRoot = fileURLToPath(new URL("../../proto/", import.meta.url));

const definition = protoLoader.loadSync(
  ["clovelly/cell/v1/cell.proto", "clovelly/control/v1/control.proto", "clovelly/verifier/v1/verifier.proto", "grpc/health/v1/health.proto"],
  { includeDirs: [protoRoot], longs: Number, enums: String, defaults: true, oneofs: true },
);

type StreamKind = "unary" | "client_stream" | "server_stream" | "bidi";

const STREAM_KINDS: Record<StreamKind, [requestStream: boolean, responseStream: boolean]> = {
  unary: [false, false],
  client_stream: [true, false],
  server_stream: [false, true],
  bidi: [true, true],
};

/**
 * Looks up a loaded service and checks that each method the interface `S` names exists
 * with the stream kind given, so the hand-written interfaces cannot drift from the protos
 * in method names or streaming. Message shapes are mirrored by hand above.
 */
function service<S>(name: string, methods: Record<keyof S, StreamKind>): S {
  const loaded = definition[name];
  if (loaded === undefined || "format" in loaded) {
    throw new Error(`${name} is not a service in the bundled protos`);
  }
  for (const [method, kind] of Object.entries<StreamKind>(methods)) {
    const found = loaded[method];
    const [requestStream, responseStream] = STREAM_KINDS[kind];
    if (found?.requestStream !== requestStream || found.responseStream !== responseStream) {
      throw new Error(`${name}/${method} is not a ${kind} method in the bundled protos`);
    }
  }
  // The trust boundary between the .proto files and this file's types: proto-loader types
  // every message as `object`, and the checks above pin what can be checked at runtime.
  return loaded as unknown as S;
}

export const cellService = service<CellService>("clovelly.cell.v1.Cell", {
  CreateSandbox: "unary",
  Exec: "bidi",
  ReadFile: "server_stream",
  WriteFile: "client_stream",
  Kill: "unary",
  GetReceipt: "unary",
});

export const controlService = service<ControlService>("clovelly.control.v1.Control", {
  PlaceSandbox: "unary",
  PutPool: "unary",
  LocateSandbox: "unary",
  ReleaseSandbox: "unary",
  PutCredential: "unary",
  PutTemplate: "client_stream",
  GetTemplate: "unary",
});

export const verifierService = service<VerifierService>("clovelly.verifier.v1.Verifier", {
  SealCredential: "unary",
  SealTemplateKey: "unary",
  ListReceipts: "unary",
  GetEgressLog: "unary",
});

export const healthService = service<HealthService>("grpc.health.v1.Health", {
  Check: "unary",
});
