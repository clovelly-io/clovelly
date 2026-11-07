// The control plane client: placement, and storing sealed credentials and encrypted
// templates. It never sees content, secrets, template keys or access keys.
import * as grpc from "@grpc/grpc-js";
import { ControlPlaneUnavailable, clovellyError, invalidRequest } from "./errors.js";
import * as pb from "./proto.js";
import { type ClientMethod, clientStream, unary } from "./rpc.js";
import { parseTemplate, type Template } from "./template.js";

/** A cold create blocks while a cell boots, so placement may take minutes. */
const PLACE_DEADLINE_MS = 330_000;
const LOCATE_DEADLINE_MS = 30_000;
const RELEASE_DEADLINE_MS = 10_000;
/** A whole template upload: 2 GB at a few MB/s, with room to spare. */
const UPLOAD_DEADLINE_MS = 3_600_000;

export interface ControlSettings {
  /** `host:port` or `https://host:port`. */
  url: string;
  /** Sent on every call as `authorization: Bearer <token>`. */
  token: string;
  /** Roots for the control plane's certificate; undefined uses the system roots. */
  ca: Buffer | undefined;
}

/** gRPC over TLS to the control plane's `Control` service, authenticated by the API token. */
export class Control {
  readonly #client: grpc.Client;

  constructor({ url, token, ca }: ControlSettings) {
    const bearer = grpc.credentials.createFromMetadataGenerator((_params, callback) => {
      const metadata = new grpc.Metadata();
      metadata.set("authorization", `Bearer ${token}`);
      callback(null, metadata);
    });
    const credentials = grpc.credentials.combineChannelCredentials(grpc.credentials.createSsl(ca ?? null), bearer);
    this.#client = new grpc.Client(target(url), credentials);
  }

  /** Picks a cell for a new sandbox, booting one when none can hold it. */
  placeSandbox(request: pb.PlaceSandboxRequest): Promise<pb.Placement> {
    return this.#unary(pb.controlService.PlaceSandbox, request, PLACE_DEADLINE_MS);
  }

  /** Sets a sub-environment's pool: its region and the customer's settings. */
  putPool(request: Partial<pb.Pool>): Promise<pb.Pool> {
    return this.#unary(pb.controlService.PutPool, request, LOCATE_DEADLINE_MS);
  }

  /** Where an existing sandbox lives. */
  locateSandbox(sandboxId: string): Promise<pb.Placement> {
    return this.#unary(pb.controlService.LocateSandbox, { sandboxId }, LOCATE_DEADLINE_MS);
  }

  /** Tells the control plane the sandbox's capacity is free again. */
  async releaseSandbox(sandboxId: string): Promise<void> {
    await this.#unary(pb.controlService.ReleaseSandbox, { sandboxId }, RELEASE_DEADLINE_MS);
  }

  /** Stores a credential sealed by the customer's verifier (ciphertext only). */
  async putCredential(request: pb.PutCredentialRequest): Promise<void> {
    await this.#unary(pb.controlService.PutCredential, request, LOCATE_DEADLINE_MS);
  }

  /**
   * Stores a template: the header, then `data` (ciphertext pieces) as data messages, each
   * pulled only once the last was sent. If `data` throws, the call is cancelled and its error
   * is thrown here.
   */
  async putTemplate(header: pb.TemplateHeader, data: AsyncIterable<Buffer>): Promise<Template> {
    async function* requests(): AsyncGenerator<pb.PutTemplateRequest> {
      yield { header };
      for await (const piece of data) yield { data: piece };
    }
    const reply = await clientStream(this.#client, pb.controlService.PutTemplate, requests(), {
      deadline: Date.now() + UPLOAD_DEADLINE_MS,
    }).catch((error: unknown) => {
      throw clovellyError(error, ControlPlaneUnavailable);
    });
    return parseTemplate(reply.template);
  }

  /** A sub-environment's template by name. */
  async getTemplate(request: pb.GetTemplateRequest): Promise<Template> {
    return parseTemplate(await this.#unary(pb.controlService.GetTemplate, request, LOCATE_DEADLINE_MS));
  }

  close(): void {
    this.#client.close();
  }

  #unary<Req, Res>(method: ClientMethod<Req, Res>, request: Req, deadlineMs: number): Promise<Res> {
    return unary(this.#client, method, request, { deadline: Date.now() + deadlineMs }).catch((error: unknown) => {
      throw clovellyError(error, ControlPlaneUnavailable);
    });
  }
}

/** The gRPC target for an API URL: `host:port` as given, or the authority of an https URL. */
function target(url: string): string {
  if (url.startsWith("https://")) return new URL(url).host;
  if (url.includes("://")) {
    throw invalidRequest(`control plane URL ${url}: use host:port or https://host:port`);
  }
  return url;
}
