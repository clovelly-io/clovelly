// Test fixtures: certificates made with the openssl CLI, and in-process fake cells, a fake
// control plane and a fake customer verifier served by grpc-js over TLS.
import { execFileSync } from "node:child_process";
import { randomBytes, X509Certificate } from "node:crypto";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as grpc from "@grpc/grpc-js";
import * as pb from "../src/proto.js";

// The tests configure every service explicitly; a developer's settings must not leak in.
for (const name of ["CLOVELLY_API_URL", "CLOVELLY_API_TOKEN", "CLOVELLY_API_CA", "CLOVELLY_VERIFIER_TOKEN", "CLOVELLY_VERIFIER_CA"]) {
  delete process.env[name];
}

/** A status a fake server ends a call with. */
export type Status = Partial<grpc.StatusObject>;

/** The signature fake cells put on their receipts (the SDK does not verify it). */
export const SIGNATURE = Buffer.from(Array.from({ length: 64 }, (_, i) => i));
/** The SDK token the fake verifier accepts. */
export const VERIFIER_TOKEN = "sdk-token";

export interface KeyPair {
  key: Buffer;
  cert: Buffer;
}

export interface Pki {
  /** Where the files live; the caller removes it. */
  dir: string;
  /** The environment CA, and the path of its PEM file. */
  ca: Buffer;
  caPath: string;
  /** Issued by the environment CA for sub-environment a of environment staging and `CELL_1`, as the verifier issues a cell's. */
  cellA: KeyPair;
  /** The same for a second cell of sub-environment a, `CELL_2`. */
  cellA2: KeyPair;
  /** Issued by the environment CA, but for sub-environment b and `CELL_B`. */
  cellB: KeyPair;
  /** Issued by the environment CA for sub-environment a alone, as before phase 12. */
  oldA: KeyPair;
  /** Self-signed, naming sub-environment a and `CELL_1`. */
  selfSigned: KeyPair;
  /** Issued by another environment's CA, naming sub-environment a and `CELL_1`. */
  otherCa: KeyPair;
  /** The control plane's: issued by the environment CA for localhost. */
  control: KeyPair;
}

/** Cells by their own names (phase 12): two of sub-environment a and one of b. */
export const CELL_1 = "cell-1.us-central1-a.a.staging.cells.clovelly.internal";
export const CELL_2 = "cell-2.us-central1-a.a.staging.cells.clovelly.internal";
export const CELL_B = "cell-1.us-central1-a.b.staging.cells.clovelly.internal";

const CONFIG = `
[req]
distinguished_name = dn
[dn]
[ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
${leaf("subenv_a", `DNS:a.staging.cells.clovelly.internal,DNS:${CELL_1}`)}
${leaf("subenv_a2", `DNS:a.staging.cells.clovelly.internal,DNS:${CELL_2}`)}
${leaf("subenv_b", `DNS:b.staging.cells.clovelly.internal,DNS:${CELL_B}`)}
${leaf("subenv_a_old", "DNS:a.staging.cells.clovelly.internal")}
${leaf("localhost", "DNS:localhost,IP:127.0.0.1")}
`;

function leaf(section: string, san: string): string {
  return `[${section}]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = ${san}`;
}

/** Makes the test PKI with EC P-256 keys. */
export function makePki(): Pki {
  const dir = mkdtempSync(join(tmpdir(), "clovelly-sdk-pki-"));
  writeFileSync(join(dir, "openssl.cnf"), CONFIG);
  const openssl = (...args: string[]) => execFileSync("openssl", args, { cwd: dir, stdio: ["ignore", "ignore", "pipe"] });
  const read = (name: string): KeyPair => ({
    key: readFileSync(join(dir, `${name}.key`)),
    cert: readFileSync(join(dir, `${name}.pem`)),
  });
  const keygen = (name: string) => openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", `${name}.key`);
  const selfSign = (name: string, extensions: string) => {
    keygen(name);
    openssl("req", "-x509", "-new", "-key", `${name}.key`, "-sha256", "-days", "1", "-subj", `/CN=${name}`,
      "-config", "openssl.cnf", "-extensions", extensions, "-out", `${name}.pem`);
    return read(name);
  };
  const issue = (name: string, extensions: string, ca: string) => {
    keygen(name);
    openssl("req", "-new", "-key", `${name}.key`, "-subj", `/CN=${name}`, "-config", "openssl.cnf", "-out", `${name}.csr`);
    openssl("x509", "-req", "-in", `${name}.csr`, "-CA", `${ca}.pem`, "-CAkey", `${ca}.key`, "-CAcreateserial",
      "-days", "1", "-sha256", "-extfile", "openssl.cnf", "-extensions", extensions, "-out", `${name}.pem`);
    return read(name);
  };
  const ca = selfSign("env-ca", "ca");
  selfSign("other-ca", "ca");
  return {
    dir,
    ca: ca.cert,
    caPath: join(dir, "env-ca.pem"),
    cellA: issue("cell-a", "subenv_a", "env-ca"),
    cellA2: issue("cell-a2", "subenv_a2", "env-ca"),
    cellB: issue("cell-b", "subenv_b", "env-ca"),
    oldA: issue("old-a", "subenv_a_old", "env-ca"),
    selfSigned: selfSign("self-signed", "subenv_a"),
    otherCa: issue("other-ca-cell", "subenv_a", "other-ca"),
    control: issue("control", "localhost", "env-ca"),
  };
}

/** A refusal as a cell or the control plane sends it: a status with the `clovelly-error` trailer. */
export function refusal(reason: string, code: grpc.status, extra: Record<string, string> = {}): Status {
  const metadata = new grpc.Metadata();
  metadata.set("clovelly-error", reason);
  for (const [key, value] of Object.entries(extra)) metadata.set(key, value);
  return { code, details: `refused: ${reason}`, metadata };
}

async function listen(server: grpc.Server, host: string, { key, cert }: KeyPair): Promise<number> {
  const credentials = grpc.ServerCredentials.createSsl(null, [{ private_key: key, cert_chain: cert }], false);
  return new Promise((resolve, reject) => {
    server.bindAsync(`${host}:0`, credentials, (error, port) => (error ? reject(error) : resolve(port)));
  });
}

export interface FakeSandbox {
  request: pb.CreateSandboxRequest;
  key: Buffer;
  cpuHalves: number;
  memoryGib: number;
  timeoutSecs: number;
  ended: boolean;
  execs: number;
  /** Sizes of the stdin messages each Exec received. */
  stdinChunks: number[][];
  files: Map<string, Buffer>;
}

/**
 * A cell: the Cell and Health services over TLS with the given certificate. Exec echoes
 * stdin to stdout and writes its argv as JSON to stderr; `print(6*7)` prints 42.
 */
export class FakeCell {
  /** Every RPC that reached this cell, health probes included. */
  readonly calls: string[] = [];
  /** `getPeer()` of every call: one entry means one connection. */
  readonly peers = new Set<string>();
  readonly sandboxes = new Map<string, FakeSandbox>();
  /** When set, CreateSandbox refuses with it. */
  refuseCreate: Status | undefined;
  address = "";
  /** The DER certificate the cell serves, which its receipts carry. */
  cert = Buffer.alloc(0);
  readonly #server = new grpc.Server();
  #hold: { count: number; started: number; waiting: (() => void)[] } | undefined;

  static async start(pair: KeyPair): Promise<FakeCell> {
    const cell = new FakeCell();
    cell.cert = new X509Certificate(pair.cert).raw;
    cell.#server.addService(pb.healthService, {
      Check: cell.#check,
    });
    cell.#server.addService(pb.cellService, {
      CreateSandbox: cell.#createSandbox,
      Exec: cell.#exec,
      ReadFile: cell.#readFile,
      WriteFile: cell.#writeFile,
      Kill: cell.#kill,
      GetReceipt: cell.#getReceipt,
    });
    cell.address = `127.0.0.1:${await listen(cell.#server, "127.0.0.1", pair)}`;
    return cell;
  }

  stop(): void {
    this.#server.forceShutdown();
  }

  /** Makes the next `count` Execs hold their output until all of them have started. */
  holdExecs(count: number): void {
    this.#hold = { count, started: 0, waiting: [] };
  }

  #record(method: string, call: { getPeer(): string }): void {
    this.calls.push(method);
    this.peers.add(call.getPeer());
  }

  /** The sandbox a request names if its key opens it; otherwise `fail` gets the refusal. */
  #open({ sandboxId, accessKey }: pb.SandboxRequest, fail: (status: Status) => void): FakeSandbox | undefined {
    const sandbox = this.sandboxes.get(sandboxId);
    if (sandbox === undefined) fail(refusal("NO_SUCH_SANDBOX", grpc.status.NOT_FOUND));
    else if (!sandbox.key.equals(accessKey)) fail(refusal("PERMISSION", grpc.status.PERMISSION_DENIED));
    else return sandbox;
    return undefined;
  }

  #receipt(sandboxId: string, sandbox: FakeSandbox): pb.Receipt {
    const kind = sandbox.ended ? "killed" : "running";
    const { templateDigest, volume } = sandbox.request;
    const sandboxDoc = { id: sandboxId, template_digest: templateDigest || null, volume_id: volume || null };
    const json = { v: 1, env: "staging", subenv: "a", sandbox: sandboxDoc, exit: { kind } };
    return {
      json: Buffer.from(JSON.stringify(json)),
      signature: SIGNATURE,
      exitKind: sandbox.ended ? "EXIT_KIND_KILLED" : "EXIT_KIND_RUNNING",
      cellCert: this.cert,
      final: sandbox.ended,
    };
  }

  #check: grpc.handleUnaryCall<pb.HealthCheckRequest, pb.HealthCheckResponse> = (call, callback) => {
    this.#record("Health/Check", call);
    callback(null, { status: "SERVING" });
  };

  #createSandbox: grpc.handleUnaryCall<pb.CreateSandboxRequest, pb.CreateSandboxResponse> = (call, callback) => {
    this.#record("CreateSandbox", call);
    const { sandboxId, accessKey, cpuHalves, memoryGib, timeoutSecs } = call.request;
    if (this.refuseCreate !== undefined) return callback(this.refuseCreate);
    if (!/^[0-9a-f]{32}$/.test(sandboxId)) return callback(refusal("INVALID_SANDBOX_ID", grpc.status.INVALID_ARGUMENT));
    if (this.sandboxes.has(sandboxId)) return callback(refusal("SANDBOX_EXISTS", grpc.status.ALREADY_EXISTS));
    this.sandboxes.set(sandboxId, {
      request: call.request,
      key: accessKey,
      cpuHalves,
      memoryGib,
      timeoutSecs,
      ended: false,
      execs: 0,
      stdinChunks: [],
      files: new Map(),
    });
    callback(null, { startedUnixMs: Date.now(), runscMs: 7 });
  };

  #exec: grpc.handleBidiStreamingCall<pb.Decoded<pb.ExecRequestMsg>, pb.ExecResponse> = (call) => {
    this.#record("Exec", call);
    let started: { start: pb.ExecStart; sandbox: FakeSandbox; chunks: number[] } | undefined;
    const stdin: Buffer[] = [];
    call.on("data", (request: pb.Decoded<pb.ExecRequestMsg>) => {
      switch (request.msg) {
        case "start": {
          const sandbox = this.#open(request.start, (status) => call.emit("error", status));
          if (sandbox === undefined) return;
          if (sandbox.ended) return call.emit("error", refusal("SANDBOX_ENDED", grpc.status.FAILED_PRECONDITION));
          started = { start: request.start, sandbox, chunks: [] };
          sandbox.stdinChunks.push(started.chunks);
          break;
        }
        case "stdin":
          stdin.push(request.stdin);
          started?.chunks.push(request.stdin.length);
          break;
        case "stdinEof":
          if (started !== undefined) void this.#run(call, started.start, started.sandbox, Buffer.concat(stdin));
          break;
      }
    });
  };

  async #run(
    call: grpc.ServerDuplexStream<pb.Decoded<pb.ExecRequestMsg>, pb.ExecResponse>,
    { args }: pb.ExecStart,
    sandbox: FakeSandbox,
    stdin: Buffer,
  ): Promise<void> {
    await this.#barrier();
    const first = sandbox.execs++ === 0;
    const python = args.join(" ").includes("print(6*7)");
    call.write({ stdout: python ? Buffer.from("42\n") : stdin });
    call.write({ stderr: Buffer.from(JSON.stringify(args)) });
    call.write({ exit: { code: 0, firstExecMs: first ? 5 : 0, sandboxEnded: "EXIT_KIND_UNSPECIFIED" } });
    call.end();
  }

  async #barrier(): Promise<void> {
    const hold = this.#hold;
    if (hold === undefined) return;
    if (++hold.started < hold.count) return new Promise((resolve) => hold.waiting.push(resolve));
    this.#hold = undefined;
    for (const release of hold.waiting) release();
  }

  #readFile: grpc.handleServerStreamingCall<pb.ReadFileRequest, pb.FileChunk> = (call) => {
    this.#record("ReadFile", call);
    const sandbox = this.#open(call.request, (status) => call.emit("error", status));
    if (sandbox === undefined) return;
    const data = sandbox.files.get(call.request.path);
    if (data === undefined) return call.emit("error", refusal("NO_SUCH_FILE", grpc.status.NOT_FOUND));
    for (let offset = 0; offset < data.length; offset += 50_000) call.write({ data: data.subarray(offset, offset + 50_000) });
    call.end();
  };

  #writeFile: grpc.handleClientStreamingCall<pb.Decoded<pb.WriteFileRequestMsg>, pb.WriteFileResponse> = (call, callback) => {
    this.#record("WriteFile", call);
    let header: pb.WriteFileHeader | undefined;
    const data: Buffer[] = [];
    call.on("data", (request: pb.Decoded<pb.WriteFileRequestMsg>) => {
      if (request.msg === "header") header = request.header;
      else data.push(request.data);
    });
    call.on("end", () => {
      if (header === undefined) return callback(refusal("INVALID_REQUEST", grpc.status.INVALID_ARGUMENT));
      const sandbox = this.#open(header, callback);
      if (sandbox === undefined) return;
      const contents = Buffer.concat(data);
      sandbox.files.set(header.path, contents);
      callback(null, { bytesWritten: contents.length });
    });
  };

  #kill: grpc.handleUnaryCall<pb.SandboxRequest, pb.Receipt> = (call, callback) => {
    this.#record("Kill", call);
    const sandbox = this.#open(call.request, callback);
    if (sandbox === undefined) return;
    if (sandbox.ended) return callback(refusal("SANDBOX_ENDED", grpc.status.FAILED_PRECONDITION));
    sandbox.ended = true;
    callback(null, this.#receipt(call.request.sandboxId, sandbox));
  };

  #getReceipt: grpc.handleUnaryCall<pb.SandboxRequest, pb.Receipt> = (call, callback) => {
    this.#record("GetReceipt", call);
    const sandbox = this.#open(call.request, callback);
    if (sandbox === undefined) return;
    callback(null, this.#receipt(call.request.sandboxId, sandbox));
  };
}

/** One PutTemplate stream as the fake control plane received it. */
export interface Upload {
  header: pb.TemplateHeader;
  data: Buffer[];
}

/**
 * A control plane that places sandboxes on `cells` in order, skipping those to avoid, and
 * stores templates whose upload stream completed (every stream is in `uploads`).
 */
export class FakeControl {
  /** Every RPC that reached it. */
  readonly calls: string[] = [];
  readonly uploads: Upload[] = [];
  /** Stored templates by `<subenv>/<name>`. */
  readonly templates = new Map<string, pb.TemplateInfo>();
  readonly placeRequests: pb.PlaceSandboxRequest[] = [];
  readonly released: string[] = [];
  /** The `authorization` header of every call. */
  readonly authorizations: string[] = [];
  readonly placements = new Map<string, pb.Placement>();
  /** The cells PlaceSandbox places on; `name` defaults to cell-1 of the request's sub-environment. */
  cells: { id: string; address: string; name?: string }[] = [];
  /** When set, PlaceSandbox refuses with it. */
  refusePlace: Status | undefined;
  /** The published regions PutPool accepts, and the pools it was given. */
  readonly regions = ["us-central1", "europe-west4", "asia-southeast1"];
  readonly pools = new Map<string, Partial<pb.Pool>>();
  /** When set, rewrites every placement PlaceSandbox and LocateSandbox answer with. */
  tamper: ((placement: pb.Placement) => pb.Placement) | undefined;
  address = "";
  readonly #server = new grpc.Server();

  static async start(pair: KeyPair): Promise<FakeControl> {
    const control = new FakeControl();
    control.#server.addService(pb.controlService, {
      PlaceSandbox: control.#placeSandbox,
      PutPool: control.#putPool,
      LocateSandbox: control.#locateSandbox,
      ReleaseSandbox: control.#releaseSandbox,
      PutTemplate: control.#putTemplate,
      GetTemplate: control.#getTemplate,
    });
    control.address = `localhost:${await listen(control.#server, "localhost", pair)}`;
    return control;
  }

  stop(): void {
    this.#server.forceShutdown();
  }

  #record(metadata: grpc.Metadata, method: string): void {
    this.calls.push(method);
    this.authorizations.push(...metadata.get("authorization").map(String));
  }

  #putPool: grpc.handleUnaryCall<Partial<pb.Pool>, pb.Pool> = (call, callback) => {
    this.#record(call.metadata, "PutPool");
    const request = call.request;
    const region = request.region ?? "";
    if (!this.regions.includes(region)) {
      return callback(refusal("UNKNOWN_REGION", grpc.status.INVALID_ARGUMENT, { "clovelly-regions": this.regions.join(",") }));
    }
    this.pools.set(request.subenvId ?? "", request);
    callback(null, {
      envId: request.envId ?? "",
      subenvId: request.subenvId ?? "",
      machineType: "c3-standard-8",
      zones: ["a", "b", "c"].map((z) => `${region}-${z}`),
      minWarmPerZone: request.minWarmPerZone ?? 0,
      idleWindowSecs: request.idleWindowSecs ?? 0,
      capSecs: 0,
      releaseId: "",
      testMetadata: {},
      region,
    });
  };

  #placeSandbox: grpc.handleUnaryCall<pb.PlaceSandboxRequest, pb.Placement> = (call, callback) => {
    this.#record(call.metadata, "PlaceSandbox");
    const request = call.request;
    this.placeRequests.push(request);
    if (this.refusePlace !== undefined) return callback(this.refusePlace);
    const cell = this.cells.find(({ id }) => !request.avoidCells.includes(id));
    if (cell === undefined) return callback(refusal("NO_CELL_CAN_HOLD", grpc.status.FAILED_PRECONDITION));
    const placement: pb.Placement = {
      sandboxId: randomBytes(16).toString("hex"),
      cellId: cell.id,
      cellAddress: cell.address,
      cellName: cell.name ?? `cell-1.us-central1-a.${request.subenvId}.${request.envId}.cells.clovelly.internal`,
      envId: request.envId,
      subenvId: request.subenvId,
      cold: false,
      size: {
        cpuHalves: request.size.cpuHalves || 2,
        memoryGib: request.size.memoryGib || 2,
      },
      timeoutSecs: request.timeoutSecs || 900,
    };
    this.placements.set(placement.sandboxId, placement);
    callback(null, this.tamper?.(placement) ?? placement);
  };

  #locateSandbox: grpc.handleUnaryCall<pb.SandboxIdRequest, pb.Placement> = (call, callback) => {
    this.#record(call.metadata, "LocateSandbox");
    const placement = this.placements.get(call.request.sandboxId);
    if (placement === undefined) return callback(refusal("NO_SUCH_SANDBOX", grpc.status.NOT_FOUND));
    callback(null, this.tamper?.(placement) ?? placement);
  };

  #releaseSandbox: grpc.handleUnaryCall<pb.SandboxIdRequest, pb.Empty> = (call, callback) => {
    this.#record(call.metadata, "ReleaseSandbox");
    this.released.push(call.request.sandboxId);
    callback(null, {});
  };

  #putTemplate: grpc.handleClientStreamingCall<pb.Decoded<pb.PutTemplateRequestMsg>, pb.PutTemplateResponse> = (call, callback) => {
    this.#record(call.metadata, "PutTemplate");
    let upload: Upload | undefined;
    call.on("data", (request: pb.Decoded<pb.PutTemplateRequestMsg>) => {
      if (request.msg === "header") this.uploads.push((upload = { header: request.header, data: [] }));
      else upload?.data.push(request.data);
    });
    // A cancelled stream never ends, so nothing is stored for it.
    call.on("end", () => {
      if (upload === undefined) return callback(refusal("INVALID_REQUEST", grpc.status.INVALID_ARGUMENT));
      const { header, data } = upload;
      const template: pb.TemplateInfo = {
        name: header.name,
        digest: header.digest,
        ciphertextBytes: data.reduce((sum, piece) => sum + piece.length, 0),
        plaintextBytes: header.plaintextBytes,
        parts: 1,
      };
      this.templates.set(`${header.subenvId}/${header.name}`, template);
      callback(null, { template });
    });
  };

  #getTemplate: grpc.handleUnaryCall<pb.GetTemplateRequest, pb.TemplateInfo> = (call, callback) => {
    this.#record(call.metadata, "GetTemplate");
    const template = this.templates.get(`${call.request.subenvId}/${call.request.name}`);
    if (template === undefined) return callback(refusal("NO_SUCH_TEMPLATE", grpc.status.NOT_FOUND));
    callback(null, template);
  };
}

/**
 * The customer's verifier, for the SDK's calls. SealTemplateKey always issues `KEY` (so tests
 * can decrypt what was uploaded) with `sealed:<digest>`; ListReceipts serves `log` filtered as
 * asked; GetEgressLog serves `egress`. Every call needs `VERIFIER_TOKEN`.
 */
export class FakeVerifier {
  static readonly KEY = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
  /** Every request that reached it, by method. */
  readonly requests: { method: string; request: unknown }[] = [];
  log: pb.LoggedReceipt[] = [];
  readonly egress = new Map<string, pb.GetEgressLogResponse>();
  /** Runs inside SealTemplateKey, before it answers. */
  onSeal: (() => void) | undefined;
  address = "";
  readonly #server = new grpc.Server();

  static async start(pair: KeyPair): Promise<FakeVerifier> {
    const verifier = new FakeVerifier();
    verifier.#server.addService(pb.verifierService, {
      SealCredential: (_call: unknown, callback: grpc.sendUnaryData<pb.SealCredentialResponse>) =>
        callback({ code: grpc.status.UNIMPLEMENTED }),
      SealTemplateKey: verifier.#sealTemplateKey,
      ListReceipts: verifier.#listReceipts,
      GetEgressLog: verifier.#getEgressLog,
    });
    verifier.address = `localhost:${await listen(verifier.#server, "localhost", pair)}`;
    return verifier;
  }

  get url(): string {
    return `https://${this.address}`;
  }

  stop(): void {
    this.#server.forceShutdown();
  }

  /** Records the call; false (and the call refused) without the SDK token. */
  #accept(method: string, call: grpc.ServerUnaryCall<unknown, unknown>, callback: (status: Status) => void): boolean {
    this.requests.push({ method, request: call.request });
    if (call.metadata.get("authorization").map(String).includes(`Bearer ${VERIFIER_TOKEN}`)) return true;
    callback({ code: grpc.status.UNAUTHENTICATED, details: "bad SDK token" });
    return false;
  }

  #sealTemplateKey: grpc.handleUnaryCall<pb.SealTemplateKeyRequest, pb.SealTemplateKeyResponse> = (call, callback) => {
    if (!this.#accept("SealTemplateKey", call, callback)) return;
    this.onSeal?.();
    callback(null, { key: FakeVerifier.KEY, sealedKey: Buffer.from(`sealed:${call.request.digest}`) });
  };

  #listReceipts: grpc.handleUnaryCall<pb.ListReceiptsRequest, pb.ListReceiptsResponse> = (call, callback) => {
    if (!this.#accept("ListReceipts", call, callback)) return;
    const { subenvId, sandboxIds } = call.request;
    const wanted = ({ receipt }: pb.LoggedReceipt) => {
      const doc: { subenv?: string; sandbox: { id: string } } = JSON.parse(receipt.toString());
      return (subenvId === "" || doc.subenv === subenvId) && (sandboxIds.length === 0 || sandboxIds.includes(doc.sandbox.id));
    };
    callback(null, { receipts: this.log.filter(wanted) });
  };

  #getEgressLog: grpc.handleUnaryCall<pb.GetEgressLogRequest, pb.GetEgressLogResponse> = (call, callback) => {
    if (!this.#accept("GetEgressLog", call, callback)) return;
    const log = this.egress.get(call.request.sandboxId);
    if (log === undefined) return callback({ code: grpc.status.NOT_FOUND, details: "no final receipt for that sandbox" });
    callback(null, log);
  };
}
