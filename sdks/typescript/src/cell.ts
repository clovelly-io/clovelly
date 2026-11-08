// One TLS connection to a cell, verified before anything that carries data is sent.
import { setTimeout as sleep } from "node:timers/promises";
import * as grpc from "@grpc/grpc-js";
import {
  CellUnavailable,
  CellVerificationError,
  type CellVerificationKind,
  clovellyError,
  isServiceError,
  protocolError,
} from "./errors.js";
import * as pb from "./proto.js";
import { type ExitKind, parseReceipt, type Receipt } from "./receipts.js";
import { bidiStream, type ClientMethod, clientStream, serverStream, unary } from "./rpc.js";

/** Bytes per stdin and file-data message. */
const CHUNK_BYTES = 64 * 1024;
const PROBE_DEADLINE_MS = 15_000;
// How long a cell nobody can reach yet is waited for. Through the relay a placed cell answers at
// once (phase 12); the wait covers a relay instance being replaced, and a control plane from
// before the relay, whose per-cell forwarding rules answered a client tens of seconds late.
const CONNECT_WAIT_MS = 90_000;

export interface ExecResult {
  /** The exit status, or 128 + signal. */
  readonly exitCode: number;
  readonly stdout: Buffer;
  readonly stderr: Buffer;
  /**
   * For a sandbox's first exec only: milliseconds from its runsc create call to this exec's
   * first stdout byte, measured in the cell.
   */
  readonly firstExecMs: number | undefined;
  /** `performance.now()` when the first stdout chunk arrived. */
  readonly firstStdoutAt: number | undefined;
  /** Set when the sandbox itself ended while this exec ran, e.g. `"revoked"`. */
  readonly sandboxEnded: ExitKind | undefined;
}

/** A sandbox on a cell and the access key that opens it. */
export interface SandboxKey {
  sandboxId: string;
  key: Buffer;
}

export interface CreateSandboxParams extends SandboxKey {
  /** vCPUs in halves (2 is one vCPU). */
  cpuHalves: number;
  memoryGib: number;
  timeoutSecs: number;
  /** The sandbox's main process (argv); empty or absent keeps it idle until Kill or its timeout. */
  command?: readonly string[];
  env?: Readonly<Record<string, string>>;
  /** The template's digest (64 lowercase hex) as its read-only root; empty or absent: the base bundle. */
  templateDigest?: string;
  /** A volume of the sub-environment, mounted at /volume; empty or absent: none. */
  volume?: string;
  /** The volume's size in GiB when it is created; 0 or absent: 1. */
  volumeGib?: number;
}

export interface ExecParams extends SandboxKey {
  /** argv, run directly (no shell). */
  args: readonly string[];
  stdin?: Buffer | string;
  env?: Readonly<Record<string, string>>;
  /** Working directory; empty or absent is "/". */
  cwd?: string;
  /** Kills the process after this many seconds; 0 or absent means only the sandbox's timeout. */
  timeoutSecs?: number;
}

export interface FileParams extends SandboxKey {
  path: string;
}

/**
 * A cell: one gRPC channel over TLS to its region's relay, `address`, with the TLS server name
 * and HTTP/2 authority set to the cell's own name, `serverName`
 * (`<instance>.<zone>.<subenv>.<env>.cells.clovelly.internal`). The relay routes by that name
 * and terminates nothing; the channel pins the environment CA and requires the certificate to
 * carry the name by standard hostname verification. Every sandbox on the cell shares it; gRPC
 * multiplexes their streams.
 *
 * Each RPC waits for `verify()` first, so nothing but the empty health probe is ever sent
 * before the cell has been verified, and gRPC sends even that only after the handshake has
 * verified the certificate. Get one from `Environment.cell`, which caches it per address
 * and name.
 */
export class Cell {
  readonly address: string;
  readonly serverName: string;
  readonly #client: grpc.Client;
  #ready: Promise<void> | undefined;
  #verified = false;
  #closed = false;

  constructor(address: string, serverName: string, ca: Buffer) {
    this.address = address;
    this.serverName = serverName;
    this.#client = new grpc.Client(address, grpc.credentials.createSsl(ca), {
      "grpc.ssl_target_name_override": serverName,
      "grpc.default_authority": serverName,
      // Reconnect within 2 s, not gRPC's growing backoff: when one of a region's relay
      // instances goes, the next connection lands on another (phase 12).
      "grpc.max_reconnect_backoff_ms": 2_000,
    });
  }

  /** True once `verify()` has succeeded. */
  get verified(): boolean {
    return this.#verified;
  }

  /** True after `close()`, which a verification failure also calls. */
  get closed(): boolean {
    return this.#closed;
  }

  /**
   * Connects and checks the cell: the TLS handshake must verify its certificate, then the
   * health probe must answer SERVING. Shared by concurrent callers and memoised once it
   * succeeds. Throws `CellVerificationError` if the certificate is refused (the cell is then
   * closed for good) and `CellUnavailable` if it cannot be reached (a later call tries again).
   */
  verify(): Promise<void> {
    this.#ready ??= this.#probe().then(
      () => {
        this.#verified = true;
      },
      (error: unknown) => {
        if (error instanceof CellVerificationError) this.close();
        else this.#ready = undefined;
        throw error;
      },
    );
    return this.#ready;
  }

  async #probe(): Promise<void> {
    const giveUp = Date.now() + CONNECT_WAIT_MS;
    for (let attempt = 1; ; attempt++) {
      try {
        return await this.#check();
      } catch (error) {
        const transient =
          error instanceof CellUnavailable || (error instanceof CellVerificationError && error.kind === "handshake");
        if (!transient || Date.now() >= giveUp) throw error;
      }
      await sleep(Math.min(attempt, 5) * 1000);
    }
  }

  /** One health probe; throws the typed reason when the cell is not verified and serving. */
  async #check(): Promise<void> {
    const { status } = await unary(this.#client, pb.healthService.Check, { service: "" }, {
      deadline: Date.now() + PROBE_DEADLINE_MS,
    }).catch((error: unknown) => {
      if (!isServiceError(error)) throw error;
      const kind = error.code === grpc.status.UNAVAILABLE ? tlsFailure(error.details) : undefined;
      throw kind === undefined
        ? clovellyError(error, CellUnavailable)
        : new CellVerificationError(kind, this.address, this.serverName, error);
    });
    if (status !== "SERVING") {
      throw new CellUnavailable(`cell ${this.address} health is ${status}`, { code: grpc.status.UNAVAILABLE });
    }
  }

  /** Starts a sandbox on this cell (`Cell.CreateSandbox`). */
  async createSandbox(params: CreateSandboxParams): Promise<pb.CreateSandboxResponse> {
    return this.#unary(pb.cellService.CreateSandbox, {
      sandboxId: params.sandboxId,
      accessKey: params.key,
      cpuHalves: params.cpuHalves,
      memoryGib: params.memoryGib,
      timeoutSecs: params.timeoutSecs,
      command: params.command ?? [],
      env: params.env ?? {},
      templateDigest: params.templateDigest ?? "",
      volume: params.volume ?? "",
      volumeGib: params.volumeGib ?? 0,
    });
  }

  /** Runs a process in a sandbox (`Cell.Exec`): sends stdin in 64 KiB chunks, then EOF. */
  async exec(params: ExecParams): Promise<ExecResult> {
    await this.verify();
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let firstStdoutAt: number | undefined;
    let exit: pb.ExecExit | undefined;
    try {
      for await (const response of bidiStream(this.#client, pb.cellService.Exec, execRequests(params))) {
        switch (response.msg) {
          case "stdout":
            firstStdoutAt ??= performance.now();
            stdout.push(response.stdout);
            break;
          case "stderr":
            stderr.push(response.stderr);
            break;
          case "exit":
            exit = response.exit;
            break;
        }
      }
    } catch (error) {
      throw clovellyError(error, CellUnavailable);
    }
    if (exit === undefined) {
      throw protocolError(`cell ${this.address}: Exec ended without an exit message`);
    }
    return {
      exitCode: exit.code,
      stdout: Buffer.concat(stdout),
      stderr: Buffer.concat(stderr),
      firstExecMs: exit.firstExecMs === 0 ? undefined : exit.firstExecMs,
      firstStdoutAt,
      sandboxEnded: pb.EXIT_KINDS[exit.sandboxEnded],
    };
  }

  /** Reads a whole file out of a sandbox (`Cell.ReadFile`). */
  async readFile({ sandboxId, key, path }: FileParams): Promise<Buffer> {
    await this.verify();
    const chunks: Buffer[] = [];
    try {
      const request = { sandboxId, accessKey: key, path };
      for await (const { data } of serverStream(this.#client, pb.cellService.ReadFile, request)) chunks.push(data);
    } catch (error) {
      throw clovellyError(error, CellUnavailable);
    }
    return Buffer.concat(chunks);
  }

  /** Writes a file in a sandbox (`Cell.WriteFile`); returns the bytes written. */
  async writeFile({ sandboxId, key, path, data }: FileParams & { data: Buffer | string }): Promise<number> {
    await this.verify();
    const header = { sandboxId, accessKey: key, path };
    const response = await clientStream(this.#client, pb.cellService.WriteFile, writeFileRequests(header, data)).catch(
      (error: unknown) => {
        throw clovellyError(error, CellUnavailable);
      },
    );
    return response.bytesWritten;
  }

  /** Ends a sandbox with exit kind "killed" (`Cell.Kill`) and returns its final receipt. */
  async kill({ sandboxId, key }: SandboxKey): Promise<Receipt> {
    return parseReceipt(await this.#unary(pb.cellService.Kill, { sandboxId, accessKey: key }));
  }

  /** A sandbox's receipt (`Cell.GetReceipt`). */
  async getReceipt({ sandboxId, key }: SandboxKey): Promise<Receipt> {
    return parseReceipt(await this.#unary(pb.cellService.GetReceipt, { sandboxId, accessKey: key }));
  }

  /** Closes the connection; later calls fail. */
  close(): void {
    this.#closed = true;
    this.#client.close();
  }

  async #unary<Req, Res>(method: ClientMethod<Req, Res>, request: Req): Promise<Res> {
    await this.verify();
    return unary(this.#client, method, request).catch((error: unknown) => {
      throw clovellyError(error, CellUnavailable);
    });
  }
}

/**
 * The TLS failure in a call's status details, as Node words it, or undefined when the
 * failure was not TLS (connection refused, timed out).
 */
function tlsFailure(details: string): CellVerificationKind | undefined {
  if (
    /self[- ]signed certificate|unable to verify the first certificate|unable to get (local )?issuer certificate|certificate signature failure|certificate has expired|certificate is not yet valid/i.test(
      details,
    )
  ) {
    return "untrusted_certificate";
  }
  if (/does not match certificate's altnames|ERR_TLS_CERT_ALTNAME_INVALID/i.test(details)) return "name_mismatch";
  if (/\bTLS\b|\bSSL\b|handshake|alert|wrong version number|certificate/i.test(details)) return "handshake";
  return undefined;
}

function* chunks(data: Buffer): Generator<Buffer> {
  for (let offset = 0; offset < data.length; offset += CHUNK_BYTES) yield data.subarray(offset, offset + CHUNK_BYTES);
}

function* execRequests({ sandboxId, key, args, stdin = "", env = {}, cwd = "", timeoutSecs = 0 }: ExecParams): Generator<pb.ExecRequest> {
  yield { start: { sandboxId, accessKey: key, args, env, cwd, timeoutSecs } };
  for (const chunk of chunks(typeof stdin === "string" ? Buffer.from(stdin) : stdin)) yield { stdin: chunk };
  yield { stdinEof: true };
}

function* writeFileRequests(header: pb.WriteFileHeader, data: Buffer | string): Generator<pb.WriteFileRequest> {
  yield { header };
  for (const chunk of chunks(typeof data === "string" ? Buffer.from(data) : data)) yield { data: chunk };
}
