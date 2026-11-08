// A sandbox: a gVisor container on one cell, opened by the access key the SDK chose.
import * as grpc from "@grpc/grpc-js";
import type { Cell, ExecResult, SandboxKey } from "./cell.js";
import type { Control } from "./control.js";
import { InvalidSandboxId, SandboxEnded, invalidRequest } from "./errors.js";
import type { Receipt } from "./receipts.js";

declare const sandboxIdBrand: unique symbol;

/**
 * A sandbox id: 32 lowercase hex characters. Fixed width, so no id is a prefix of another
 * (runsc resolves ids by prefix). Made only by `isSandboxId` and `parseSandboxId`.
 */
export type SandboxId = string & { readonly [sandboxIdBrand]: true };

/** True for 32 lowercase hex characters. */
export function isSandboxId(value: string): value is SandboxId {
  return /^[0-9a-f]{32}$/.test(value);
}

/** Checks a sandbox id; throws `InvalidSandboxId` for anything but 32 lowercase hex characters. */
export function parseSandboxId(value: string): SandboxId {
  if (!isSandboxId(value)) {
    throw new InvalidSandboxId(`sandbox id ${JSON.stringify(value)} is not 32 lowercase hex characters`, {
      code: grpc.status.INVALID_ARGUMENT,
      reason: "INVALID_SANDBOX_ID",
    });
  }
  return value;
}

/** A command as argv: a string runs under `/bin/sh -c`, an array runs as given. */
export function argv(command: string | readonly string[]): readonly string[] {
  return typeof command === "string" ? ["/bin/sh", "-c", command] : command;
}

export interface ExecOptions {
  stdin?: Buffer | string;
  env?: Readonly<Record<string, string>>;
  /** Working directory; default "/". */
  cwd?: string;
  /** Seconds before the process is killed; default only the sandbox's timeout. */
  timeout?: number;
}

/** How long each step of getting the sandbox took, in milliseconds. */
export interface SandboxTimings {
  /** In PlaceSandbox (LocateSandbox for a reconnect), summed over re-placements. */
  readonly placeMs: number;
  /** Connecting to and verifying the cell; 0 when its connection was already verified. */
  readonly connectMs: number;
  /** In CreateSandbox, refused attempts included; 0 for a reconnect. */
  readonly createMs: number;
  /** runsc create and start, as the cell measured it; 0 for a reconnect. */
  readonly runscMs: number;
}

export interface SandboxFiles {
  /** Writes a file; the parent directory must exist. */
  write(path: string, data: Buffer | string): Promise<void>;
  /** Reads a whole file; throws `FileNotFound` if it does not exist or is not readable. */
  read(path: string): Promise<Buffer>;
}

/** What `Environment` knows about a sandbox when it hands one out. */
export interface SandboxInit {
  id: SandboxId;
  key: Buffer;
  cell: Cell;
  cellId: string;
  subenv: string;
  cold: boolean;
  cpuHalves: number;
  memoryGib: number;
  timeoutSecs: number;
  timings: SandboxTimings;
  control: Control;
}

/** A running sandbox. Get one from `Environment.sandbox` or `Environment.reconnect`. */
export class Sandbox {
  readonly id: SandboxId;
  /** The access key, hex. With `id` it is all `Environment.reconnect` needs; keep it secret. */
  readonly key: string;
  readonly cellId: string;
  /** The region's relay the sandbox's cell is reached through. */
  readonly cellAddress: string;
  /** The cell's own name, which its connection is dialled and verified by. */
  readonly cellName: string;
  readonly subenv: string;
  /** A cell had to be booted for this sandbox. */
  readonly cold: boolean;
  /** vCPUs. */
  readonly cpu: number;
  /** GiB. */
  readonly memory: number;
  /** Seconds from creation until the cell ends the sandbox. */
  readonly timeout: number;
  readonly timings: SandboxTimings;
  readonly files: SandboxFiles;
  readonly #cell: Cell;
  readonly #auth: SandboxKey;
  readonly #control: Control;

  constructor(init: SandboxInit) {
    this.id = init.id;
    this.key = init.key.toString("hex");
    this.cellId = init.cellId;
    this.cellAddress = init.cell.address;
    this.cellName = init.cell.serverName;
    this.subenv = init.subenv;
    this.cold = init.cold;
    this.cpu = init.cpuHalves / 2;
    this.memory = init.memoryGib;
    this.timeout = init.timeoutSecs;
    this.timings = init.timings;
    this.#cell = init.cell;
    this.#auth = { sandboxId: init.id, key: init.key };
    this.#control = init.control;
    this.files = {
      write: async (path, data) => {
        await this.#cell.writeFile({ ...this.#auth, path, data });
      },
      read: (path) => this.#cell.readFile({ ...this.#auth, path }),
    };
  }

  /** Runs a command: a string under `/bin/sh -c`, an array as argv. Resolves when it exits. */
  async exec(command: string | readonly string[], { stdin, env, cwd, timeout = 0 }: ExecOptions = {}): Promise<ExecResult> {
    const args = argv(command);
    if (args.length === 0) throw invalidRequest("exec needs a command");
    if (!Number.isSafeInteger(timeout) || timeout < 0) throw invalidRequest(`exec timeout ${timeout} is not a whole number of seconds`);
    return this.#cell.exec({ ...this.#auth, args, stdin, env, cwd, timeoutSecs: timeout });
  }

  /** The placeholder for credential `name` (`clovelly://cred/<name>`), passed to the sandbox in place of the secret. */
  cred(name: string): string {
    return placeholder(name);
  }

  /** The sandbox's signed receipt: interim (`final` false, exit kind "running") while it runs, final once it has ended. */
  receipt(): Promise<Receipt> {
    return this.#cell.getReceipt(this.#auth);
  }

  /**
   * Kills the sandbox and returns its final signed receipt (the one it ended with if it had
   * already ended), then tells the control plane its capacity is free, best effort. The cell
   * has already appended the receipt to the customer's log.
   */
  async close(): Promise<Receipt> {
    const receipt = await this.#cell.kill(this.#auth).catch((error: unknown) => {
      if (error instanceof SandboxEnded) return this.receipt();
      throw error;
    });
    // The capacity is also freed by the cell's reports, so a failed release changes nothing.
    await this.#control.releaseSandbox(this.id).catch(() => undefined);
    return receipt;
  }
}

/**
 * The placeholder a sandbox carries for credential `name`: `clovelly://cred/<name>`. The egress
 * proxy replaces it with the secret only in requests to the credential's destination.
 */
export function placeholder(name: string): string {
  if (!/^[a-z0-9_-]{1,64}$/.test(name)) throw invalidRequest(`credential name ${JSON.stringify(name)} is not 1-64 of a-z, 0-9, '_', '-'`);
  return `clovelly://cred/${name}`;
}
