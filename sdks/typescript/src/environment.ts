// The entry point: one customer environment, its CA, and the cached cell connections.
import { randomBytes, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { Cell } from "./cell.js";
import { Control, type ControlSettings } from "./control.js";
import {
  CapacityError,
  CellDraining,
  CellRevoked,
  CrossesCellEnd,
  CrossesReleaseExpiry,
  invalidRequest,
  protocolError,
} from "./errors.js";
import type * as pb from "./proto.js";
import type { EgressLog, LoggedReceipt } from "./receipts.js";
import { argv, isSandboxId, parseSandboxId, placeholder, Sandbox, type SandboxId } from "./sandbox.js";
import {
  ciphertext,
  fileDigest,
  isTemplateDigest,
  isTemplateName,
  type Template,
  type TemplateDigest,
} from "./template.js";
import { Verifier } from "./verifier.js";

const MAX_PLACEMENTS = 3;
const MAX_TIMEOUT_SECS = 86_400;
const MAX_VOLUME_GIB = 20;

/** Cell refusals that another cell may not give: the SDK places the sandbox again elsewhere. */
const REPLACE_ON = [CapacityError, CrossesCellEnd, CrossesReleaseExpiry, CellDraining, CellRevoked];

export interface EnvironmentOptions {
  /**
   * The customer's verifier, `https://host[:port]`: it seals credentials (`putCredential`) and
   * template keys (`uploadTemplate`) and keeps the receipt log (`receipts`, `egressLog`).
   */
  verifierUrl: string;
  /** The verifier's SDK token, needed by every call to it. Default `CLOVELLY_VERIFIER_TOKEN`. */
  verifierToken?: string;
  /** Roots for the verifier's certificate (PEM, or a path). Default `CLOVELLY_VERIFIER_CA`, else the system roots. */
  verifierCa?: string | Buffer;
  /** The environment id, a DNS label. Cells are named `<subenv>.<envId>.cells.clovelly.internal`. */
  envId: string;
  /** The environment CA (PEM, or a path to a PEM file): the only trust anchor for cells. */
  caBundle: string | Buffer;
  /** The control plane, `host:port` or `https://host:port`. Default `CLOVELLY_API_URL`. */
  apiUrl?: string;
  /** The environment's API token. Default `CLOVELLY_API_TOKEN`. */
  apiToken?: string;
  /** Roots for the control plane's certificate (PEM, or a path). Default `CLOVELLY_API_CA`, else the system roots. */
  apiCa?: string | Buffer;
}

/** A sub-environment's pool as the control plane holds it. */
export interface Pool {
  subenv: string;
  /** Where its cells run. */
  region: string;
  /** The zones of the region it uses: the control plane's choice, every approved zone. */
  zones: readonly string[];
  minWarmPerZone: number;
  idleWindowSecs: number;
}

export interface SandboxOptions {
  /** Seconds, 1 to 86400. Default: the sub-environment's. */
  timeout?: number;
  /** vCPUs, a multiple of 0.5. Default: the sub-environment's. */
  cpu?: number;
  /** GiB, a whole number. Default: the sub-environment's. */
  memory?: number;
  /**
   * The sandbox's main process: a string under `/bin/sh -c`, or argv. When it exits the
   * sandbox ends. Default: none, and the sandbox lives until `close()` or its timeout.
   */
  command?: string | readonly string[];
  /** The main process's environment. */
  env?: Readonly<Record<string, string>>;
  /**
   * The sandbox's read-only root: a `Template`, its digest (64 lowercase hex) or its name,
   * which the control plane resolves in the sub-environment (pass the Template or digest to
   * pin the exact content). Default: the base bundle.
   */
  template?: Template | string;
  /** Named policies are not in v1: a sub-environment has one policy bundle. */
  policy?: never;
  /**
   * A persistent volume of the sub-environment (1-64 of a-z, 0-9, '_', '-'), mounted at
   * /volume and created on first use. One sandbox mounts it at a time.
   */
  volume?: string;
  /** The volume's size in GiB when it is created, 1 to 20; default 1. Needs `volume`. */
  volumeGib?: number;
}

/**
 * One customer environment. Creates sandboxes through the control plane and talks to their
 * cells directly, over TLS pinned to the environment CA; the control plane only says where.
 *
 * ```ts
 * const env = new Environment({ verifierUrl, envId, caBundle });
 * await env.putCredential("bank-a", "openai", key, { adapter: "bearer", destination: "api.openai.com" });
 * const template = await env.uploadTemplate("bank-a", "analyst-v3", "analyst-v3.tar.gz");
 * const sb = await env.sandbox("bank-a", { template, volume: "work", cpu: 1, memory: 2, timeout: 900 });
 * const { stdout } = await sb.exec("python3 run.py", { env: { OPENAI_API_KEY: sb.cred("openai") } });
 * const receipt = await sb.close();          // signed; the cell also appended it to the customer's log
 * const log = await env.egressLog(sb.id);    // its hash checked
 * log.matches(receipt);
 * env.close();
 * ```
 */
export class Environment {
  readonly verifierUrl: string;
  readonly envId: string;
  readonly #ca: Buffer;
  readonly #api: ControlSettings | undefined;
  readonly #cells = new Map<string, Cell>();
  readonly #verifierToken: string | undefined;
  readonly #verifierCa: Buffer | undefined;
  #control: Control | undefined;
  #verifier: Verifier | undefined;

  constructor({ verifierUrl, verifierToken, verifierCa, envId, caBundle, apiUrl, apiToken, apiCa }: EnvironmentOptions) {
    this.verifierUrl = verifierUrl;
    this.#verifierToken = verifierToken ?? setting("CLOVELLY_VERIFIER_TOKEN");
    const vca = verifierCa ?? setting("CLOVELLY_VERIFIER_CA");
    this.#verifierCa = vca === undefined ? undefined : loadPem(vca, "verifierCa");
    this.envId = label(envId, "environment id");
    this.#ca = loadPem(caBundle, "caBundle");
    const url = apiUrl ?? setting("CLOVELLY_API_URL");
    const token = apiToken ?? setting("CLOVELLY_API_TOKEN");
    const ca = apiCa ?? setting("CLOVELLY_API_CA");
    this.#api = url !== undefined && token !== undefined ? { url, token, ca: ca === undefined ? undefined : loadPem(ca, "apiCa") } : undefined;
  }

  /**
   * The cell named `name` (`<instance>.<zone>.<subenv>.<envId>.cells.clovelly.internal`) of
   * sub-environment `subenv`, through `address` (its region's relay), for talking to a cell
   * directly. One connection per address and name, shared by every sandbox on it; a cell
   * refused by verification is dropped and the next call dials afresh. A name outside
   * `subenv` throws `InvalidRequest`.
   */
  cell(address: string, name: string, subenv: string): Cell {
    const subenvId = label(subenv, "sub-environment id");
    if (!isCellName(name, this.envId, subenvId)) {
      throw invalidRequest(`cell name ${JSON.stringify(name)} is not <instance>.<zone>.${subenvId}.${this.envId}.cells.clovelly.internal`);
    }
    const serverName = name;
    // The name is part of the key: every cell of a region shares the relay's address, and a
    // connection verified for one cell must never carry another's traffic.
    const key = `${serverName} ${address}`;
    const cached = this.#cells.get(key);
    if (cached !== undefined && !cached.closed) return cached;
    const cell = new Cell(address, serverName, this.#ca);
    this.#cells.set(key, cell);
    return cell;
  }

  /**
   * Creates a sandbox in sub-environment `subenv`: the control plane places it (booting a
   * cell if none can hold it), the SDK verifies the cell and creates the sandbox there with
   * a fresh 32-byte access key. A cell that refuses for capacity, its cap, the release's
   * expiry, a drain or a revoked lease is avoided and the sandbox placed again, up to 3 times.
   * Every placement that does not become the sandbox is released, best effort. A template
   * given by name is looked up (`GetTemplate`) before placing.
   */
  async sandbox(subenv: string, options: SandboxOptions = {}): Promise<Sandbox> {
    const request = parseOptions(options);
    const subenvId = label(subenv, "sub-environment id");
    const control = this.#controlPlane();
    const templateDigest = await this.#templateDigest(control, subenvId, request.template);
    const avoidCells: string[] = [];
    const timings = { placeMs: 0, connectMs: 0, createMs: 0, runscMs: 0 };
    let cold = false;
    for (let attempt = 1; ; attempt++) {
      let started = performance.now();
      const placement = await control.placeSandbox({ envId: this.envId, subenvId, ...request.placement, avoidCells });
      timings.placeMs += performance.now() - started;
      cold ||= placement.cold;
      try {
        const { id, cell } = this.#placed(placement, subenvId);
        timings.connectMs += await connect(cell);
        const { cpuHalves, memoryGib, timeoutSecs } = sizeOf(placement);
        const key = randomBytes(32);
        started = performance.now();
        const created = await cell
          .createSandbox({
            sandboxId: id,
            key,
            cpuHalves,
            memoryGib,
            timeoutSecs,
            command: request.command,
            env: request.env,
            templateDigest,
            volume: request.volume,
            volumeGib: request.volumeGib,
          })
          .finally(() => {
            timings.createMs += performance.now() - started;
          });
        timings.runscMs = created.runscMs;
        const cellId = placement.cellId;
        return new Sandbox({ id, key, cell, cellId, subenv: subenvId, cold, cpuHalves, memoryGib, timeoutSecs, timings, control });
      } catch (error) {
        // No sandbox came of this placement: free its capacity. The cell's reports also do,
        // so a failed release changes nothing.
        await control.releaseSandbox(placement.sandboxId).catch(() => undefined);
        if (attempt < MAX_PLACEMENTS && REPLACE_ON.some((refusal) => error instanceof refusal)) {
          avoidCells.push(placement.cellId);
          continue;
        }
        throw error;
      }
    }
  }

  /**
   * Reopens an existing sandbox by id and access key (hex), from any process: the control
   * plane says which cell holds it, and GetReceipt on that cell confirms the key. With
   * `subenv`, the cell must be verified for that sub-environment and the control plane must
   * place the sandbox there (`ProtocolError` otherwise); without it, the sub-environment the
   * control plane names is used.
   */
  async reconnect(sandboxId: string, key: string, { subenv }: { subenv?: string } = {}): Promise<Sandbox> {
    const id = parseSandboxId(sandboxId);
    if (!/^[0-9a-f]{64}$/i.test(key)) throw invalidRequest("an access key is 64 hex characters");
    const keyBytes = Buffer.from(key, "hex");
    const subenvId = subenv === undefined ? undefined : label(subenv, "sub-environment id");
    const control = this.#controlPlane();
    const started = performance.now();
    const placement = await control.locateSandbox(id);
    const placeMs = performance.now() - started;
    const { cell } = this.#placed(placement, subenvId, id);
    const connectMs = await connect(cell);
    await cell.getReceipt({ sandboxId: id, key: keyBytes });
    return new Sandbox({
      id,
      key: keyBytes,
      cell,
      cellId: placement.cellId,
      subenv: placement.subenvId,
      cold: false,
      ...sizeOf(placement),
      timings: { placeMs, connectMs, createMs: 0, runscMs: 0 },
      control,
    });
  }

  /**
   * Sets `subenv`'s pool: the `region` its cells run in, from the published list
   * (docs/regions.md), warm cells per zone, and the idle window (0 is the default, 15
   * minutes). The control plane uses every approved zone of the region and moves cells between
   * them when one runs out of machines; when all of them have, `sandbox()` rejects with
   * `NoCapacity` rather than queue or go elsewhere. A region is fixed once set: another region
   * is another sub-environment. Rejects with `UnknownRegion` (its `regions` is the list) for a
   * region not offered.
   */
  async putPool(
    subenv: string,
    { region, minWarmPerZone = 0, idleWindowSecs = 0 }: { region: string; minWarmPerZone?: number; idleWindowSecs?: number },
  ): Promise<Pool> {
    const subenvId = label(subenv, "sub-environment id");
    if (![minWarmPerZone, idleWindowSecs].every((n) => Number.isInteger(n) && n >= 0)) {
      throw invalidRequest("minWarmPerZone and idleWindowSecs must be whole numbers, not negative");
    }
    const pool = await this.#controlPlane().putPool({ envId: this.envId, subenvId, region, minWarmPerZone, idleWindowSecs });
    return { subenv: pool.subenvId, region: pool.region, zones: pool.zones, minWarmPerZone: pool.minWarmPerZone, idleWindowSecs: pool.idleWindowSecs };
  }

  /**
   * Stores credential `name` for `subenv`'s sandboxes, valid only for `destination` (one
   * named host) with `adapter` ("bearer", "basic" or "query", as the sub-environment's
   * policy uses it there). The customer's verifier seals it under the sub-environment DEK;
   * the control plane stores only that ciphertext. Sandboxes see `clovelly://cred/<name>`.
   */
  async putCredential(
    subenv: string,
    name: string,
    secret: string | Buffer,
    { adapter, destination }: { adapter: "bearer" | "basic" | "query"; destination: string },
  ): Promise<void> {
    const subenvId = label(subenv, "sub-environment id");
    placeholder(name);
    if (!["bearer", "basic", "query"].includes(adapter)) throw invalidRequest(`adapter ${JSON.stringify(adapter)} is not bearer, basic or query`);
    const host = destination.toLowerCase().replace(/\.$/, "");
    if (!/^[a-z0-9_-]{1,63}(\.[a-z0-9_-]{1,63})*$/.test(host) || host.length > 253) {
      throw invalidRequest(`destination ${JSON.stringify(destination)} is not one named host`);
    }
    const raw = typeof secret === "string" ? Buffer.from(secret, "utf8") : secret;
    if (raw.length === 0 || raw.length > 16 * 1024) throw invalidRequest("a credential secret must be 1 byte to 16 KiB");
    const sealed = await this.#verifierClient().seal({ envId: this.envId, subenvId, name, adapter, destination: host, secret: raw });
    await this.#controlPlane().putCredential({ envId: this.envId, subenvId, name, sealed });
  }

  /**
   * Uploads the template at `path` (the `.tar.gz` of a sandbox root) to `subenv` as `name`
   * (1-64 of a-z, 0-9, '_', '-', '.'), replacing a template of that name, and returns it.
   *
   * The file is read twice, 1 MiB at a time: once for its SHA-256 (the digest), then to
   * encrypt and stream it. The customer's verifier issues a key for that digest
   * (`SealTemplateKey`, with the SDK token) with the same key sealed under the
   * sub-environment DEK; the control plane receives only ciphertext and the sealed key, so
   * only the sub-environment's cells can open it. A file that changes between the two reads
   * cancels the upload with `InvalidRequest`.
   */
  async uploadTemplate(subenv: string, name: string, path: string): Promise<Template> {
    const subenvId = label(subenv, "sub-environment id");
    templateName(name);
    const verifier = this.#verifierClient();
    const control = this.#controlPlane();
    const { digest, size } = await fileDigest(path);
    const hex = digest.toString("hex");
    const { key, sealedKey } = await verifier.sealTemplateKey({ envId: this.envId, subenvId, digest: hex });
    const header = { envId: this.envId, subenvId, name, digest: hex, sealedKey, plaintextBytes: size };
    // The key is needed only while the stream is encrypted; the verifier keeps the sealed copy.
    const stored = await control.putTemplate(header, ciphertext(path, key, digest, size)).finally(() => key.fill(0));
    if (stored.name !== name || stored.digest !== hex) {
      throw protocolError(`uploaded template ${name} (${hex}), the control plane stored ${stored.name} (${stored.digest})`);
    }
    return stored;
  }

  /** The template `name` of `subenv`, as the control plane stores it (`NoSuchTemplate` if there is none). */
  async template(subenv: string, name: string): Promise<Template> {
    const subenvId = label(subenv, "sub-environment id");
    return this.#controlPlane().getTemplate({ envId: this.envId, subenvId, name: templateName(name) });
  }

  /**
   * The customer's receipt log at the verifier (`ListReceipts`, with the SDK token): the
   * latest record per sandbox, for `subenv` (default: every sub-environment) and `sandboxIds`
   * (default: every sandbox).
   */
  async receipts({ subenv, sandboxIds = [] }: { subenv?: string; sandboxIds?: readonly string[] } = {}): Promise<LoggedReceipt[]> {
    const subenvId = subenv === undefined ? "" : label(subenv, "sub-environment id");
    const ids = sandboxIds.map(parseSandboxId);
    return this.#verifierClient().listReceipts({ envId: this.envId, subenvId, sandboxIds: ids });
  }

  /**
   * The egress log a sandbox's final receipt carried, from the verifier (`GetEgressLog`, with
   * the SDK token). Throws `EgressLogMismatch` unless its lines hash to the SHA-256 the
   * verifier sent with them; `matches(receipt)` then checks that against the receipt's
   * `egress_log_hash`.
   */
  async egressLog(sandboxId: string): Promise<EgressLog> {
    const id = parseSandboxId(sandboxId);
    return this.#verifierClient().egressLog(this.envId, id);
  }

  /** Closes every connection. Sandboxes keep running; `reconnect` reaches them again. */
  close(): void {
    for (const cell of this.#cells.values()) cell.close();
    this.#cells.clear();
    this.#control?.close();
    this.#control = undefined;
    this.#verifier?.close();
    this.#verifier = undefined;
  }

  /**
   * Checks a placement from the control plane and returns its sandbox id and cell. It must
   * be for this environment, for `subenvId` when given (else any sub-environment, which
   * then names the cell), for `sandboxId` when given, and well formed; `ProtocolError` if not.
   */
  #placed(placement: pb.Placement, subenvId: string | undefined, sandboxId?: SandboxId): { id: SandboxId; cell: Cell } {
    const { envId, subenvId: placedSubenv, sandboxId: placedId, cellAddress, cellName } = placement;
    const what = `the control plane's placement of sandbox ${JSON.stringify(placedId)}`;
    if (envId !== this.envId) throw protocolError(`${what} is for environment ${JSON.stringify(envId)}, not ${this.envId}`);
    if (subenvId !== undefined && placedSubenv !== subenvId) {
      throw protocolError(`${what} is for sub-environment ${JSON.stringify(placedSubenv)}, not ${subenvId}`);
    }
    if (!isLabel(placedSubenv)) throw protocolError(`${what} names sub-environment ${JSON.stringify(placedSubenv)}, not a DNS label`);
    if (!isSandboxId(placedId)) throw protocolError(`${what}: the id is not 32 lowercase hex characters`);
    if (sandboxId !== undefined && placedId !== sandboxId) throw protocolError(`${what} answers for another sandbox than ${sandboxId}`);
    if (!isAddress(cellAddress)) throw protocolError(`${what}: cell address ${JSON.stringify(cellAddress)} is not host:port`);
    // The name pins the sub-environment: a control plane naming another sub-environment's cell
    // is refused here, before anything is dialled.
    if (!isCellName(cellName, envId, placedSubenv)) {
      throw protocolError(`${what}: cell name ${JSON.stringify(cellName)} is not <instance>.<zone>.${placedSubenv}.${envId}.cells.clovelly.internal`);
    }
    return { id: placedId, cell: this.cell(cellAddress, cellName, placedSubenv) };
  }

  /** The digest a sandbox's template resolves to; empty for the base bundle. */
  async #templateDigest(control: Control, subenvId: string, template: TemplateRef): Promise<string> {
    switch (template.by) {
      case "none":
        return "";
      case "digest":
        return template.digest;
      case "name":
        return (await control.getTemplate({ envId: this.envId, subenvId, name: template.name })).digest;
    }
  }

  #verifierClient(): Verifier {
    if (this.#verifierToken === undefined) {
      throw invalidRequest("calls to the verifier need its SDK token: set verifierToken or CLOVELLY_VERIFIER_TOKEN");
    }
    this.#verifier ??= new Verifier(this.verifierUrl, this.#verifierToken, this.#verifierCa);
    return this.#verifier;
  }

  #controlPlane(): Control {
    if (this.#api === undefined) {
      throw invalidRequest("no control plane: set apiUrl and apiToken, or CLOVELLY_API_URL and CLOVELLY_API_TOKEN");
    }
    this.#control ??= new Control(this.#api);
    return this.#control;
  }
}

/** Milliseconds spent verifying `cell`; 0 when it was already verified. */
async function connect(cell: Cell): Promise<number> {
  if (cell.verified) return 0;
  const started = performance.now();
  await cell.verify();
  return performance.now() - started;
}

/**
 * The size and timeout the control plane placed, its defaults filled in. The cell refuses
 * zeros, so a placement without them fails loudly there.
 */
function sizeOf({ size, timeoutSecs }: pb.Placement) {
  return { cpuHalves: size?.cpuHalves ?? 0, memoryGib: size?.memoryGib ?? 0, timeoutSecs };
}

/** How a sandbox's template was given: pinned by digest, to be looked up by name, or none. */
type TemplateRef = { by: "digest"; digest: TemplateDigest } | { by: "name"; name: string } | { by: "none" };

interface SandboxSpec {
  placement: Pick<pb.PlaceSandboxRequest, "size" | "timeoutSecs">;
  command: readonly string[];
  env: Readonly<Record<string, string>>;
  template: TemplateRef;
  /** Empty: none. */
  volume: string;
  /** 0: the default. */
  volumeGib: number;
}

function templateRef(template: Template | string | undefined): TemplateRef {
  if (template === undefined) return { by: "none" };
  const digest = typeof template === "string" ? template : template.digest;
  if (isTemplateDigest(digest)) return { by: "digest", digest };
  if (typeof template !== "string") throw invalidRequest(`template digest ${JSON.stringify(digest)} is not 64 lowercase hex characters`);
  return { by: "name", name: templateName(template) };
}

/** Checks `SandboxOptions` and turns them into wire values; 0 means the sub-environment default. */
function parseOptions({ timeout, cpu, memory, command, env = {}, template, policy, volume, volumeGib }: SandboxOptions): SandboxSpec {
  if (policy !== undefined) throw invalidRequest("policy is not accepted: a sub-environment has one policy bundle");
  if (volume !== undefined && !/^[a-z0-9_-]{1,64}$/.test(volume)) {
    throw invalidRequest(`volume ${JSON.stringify(volume)} is not 1-64 of a-z, 0-9, '_', '-'`);
  }
  if (volumeGib !== undefined && volume === undefined) throw invalidRequest("volumeGib needs a volume");
  if (volumeGib !== undefined && !(Number.isSafeInteger(volumeGib) && volumeGib >= 1 && volumeGib <= MAX_VOLUME_GIB)) {
    throw invalidRequest(`volumeGib ${volumeGib} is not a whole number of GiB from 1 to ${MAX_VOLUME_GIB}`);
  }
  if (cpu !== undefined && !(cpu > 0 && Number.isSafeInteger(cpu * 2))) {
    throw invalidRequest(`cpu ${cpu} is not a positive multiple of 0.5 vCPU`);
  }
  if (memory !== undefined && !(memory > 0 && Number.isSafeInteger(memory))) {
    throw invalidRequest(`memory ${memory} is not a positive whole number of GiB`);
  }
  if (timeout !== undefined && !(timeout > 0 && timeout <= MAX_TIMEOUT_SECS && Number.isSafeInteger(timeout))) {
    throw invalidRequest(`timeout ${timeout} is not a whole number of seconds from 1 to ${MAX_TIMEOUT_SECS}`);
  }
  return {
    placement: { size: { cpuHalves: (cpu ?? 0) * 2, memoryGib: memory ?? 0 }, timeoutSecs: timeout ?? 0 },
    command: command === undefined ? [] : argv(command),
    env,
    template: templateRef(template),
    volume: volume ?? "",
    volumeGib: volumeGib ?? 0,
  };
}

/** Checks a template name; throws `InvalidRequest` if it is not 1-64 of a-z, 0-9, '_', '-', '.'. */
function templateName(name: string): string {
  if (!isTemplateName(name)) throw invalidRequest(`template name ${JSON.stringify(name)} is not 1-64 of a-z, 0-9, '_', '-', '.'`);
  return name;
}

/** True for a DNS label (1-63 of a-z, 0-9, '-', no leading or trailing '-'), as the cell's SAN needs. */
function isLabel(value: string): boolean {
  return /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(value);
}

/** True for one cell's name in this environment and sub-environment: `<instance>.<zone>.<subenv>.<env>.cells.clovelly.internal`. */
function isCellName(value: string, envId: string, subenvId: string): boolean {
  const labels = value.split(".");
  return (
    labels.length === 7 &&
    labels.slice(0, 2).every(isLabel) &&
    labels.slice(2).join(".") === `${subenvId}.${envId}.cells.clovelly.internal`
  );
}

/** Checks a caller's environment or sub-environment id; throws `InvalidRequest` if it is not a DNS label. */
function label(value: string, what: string): string {
  if (!isLabel(value)) throw invalidRequest(`${what} ${JSON.stringify(value)} is not a DNS label`);
  return value;
}

/** True for `host:port`: a host name, IPv4 or bracketed IPv6 address, and a port from 1 to 65535. */
function isAddress(value: string): boolean {
  const match = /^(?:\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+):(\d{1,5})$/.exec(value);
  const port = Number(match?.[1]);
  return port >= 1 && port <= 65_535;
}

/** PEM given inline or as a path, checked to hold a certificate. */
function loadPem(input: string | Buffer, what: string): Buffer {
  const pem = typeof input !== "string" ? input : input.includes("-----BEGIN") ? Buffer.from(input) : readFileSync(input);
  try {
    new X509Certificate(pem);
  } catch {
    throw invalidRequest(`${what} is not a PEM certificate`);
  }
  return pem;
}

function setting(name: string): string | undefined {
  return process.env[name] || undefined;
}
