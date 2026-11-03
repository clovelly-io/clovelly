// The customer's verifier, as the SDK calls it: SealCredential, SealTemplateKey,
// ListReceipts and GetEgressLog, each authenticated by the SDK token. The SDK sends a
// credential's secret to the customer's own verifier over TLS and gets back ciphertext
// sealed under the sub-environment DEK and bound to the credential's name, adapter and
// destination; for a template it gets a fresh key and the same key sealed to the
// sub-environment. The SDK never holds a DEK. The receipt log the verifier keeps is read
// back with the same token.
import * as grpc from "@grpc/grpc-js";
import { type ClovellyError, SandboxNotFound, protocolError, verifierError } from "./errors.js";
import * as pb from "./proto.js";
import { type EgressLog, type LoggedReceipt, parseEgressLog, parseLoggedReceipt } from "./receipts.js";
import { type ClientMethod, unary } from "./rpc.js";
import type { SandboxId } from "./sandbox.js";

const DEADLINE_MS = 30_000;
const TEMPLATE_KEY_BYTES = 32;

/** `https://host[:port]` as a gRPC target. */
export function verifierTarget(url: string): string {
  const u = new URL(url);
  if (u.protocol !== "https:" || u.hostname === "" || (u.pathname !== "/" && u.pathname !== "")) {
    throw new Error(`verifier URL ${JSON.stringify(url)} must be https://host[:port]`);
  }
  return `${u.hostname}:${u.port === "" ? "443" : u.port}`;
}

/** gRPC over TLS to the verifier (`ca`, else the system roots), authenticated by the SDK token. */
export class Verifier {
  readonly #client: grpc.Client;

  constructor(url: string, token: string, ca: Buffer | undefined) {
    const bearer = grpc.credentials.createFromMetadataGenerator((_params, callback) => {
      const metadata = new grpc.Metadata();
      metadata.set("authorization", `Bearer ${token}`);
      callback(null, metadata);
    });
    const credentials = grpc.credentials.combineChannelCredentials(grpc.credentials.createSsl(ca ?? null), bearer);
    this.#client = new grpc.Client(verifierTarget(url), credentials);
  }

  /** The sealed credential (JSON bytes). */
  async seal(request: pb.SealCredentialRequest): Promise<Buffer> {
    return (await this.#unary(pb.verifierService.SealCredential, request)).sealed;
  }

  /** A fresh 32-byte key for the template with this digest, and the same key sealed under the sub-environment DEK. */
  async sealTemplateKey(request: pb.SealTemplateKeyRequest): Promise<pb.SealTemplateKeyResponse> {
    const reply = await this.#unary(pb.verifierService.SealTemplateKey, request);
    if (reply.key.length !== TEMPLATE_KEY_BYTES || reply.sealedKey.length === 0) {
      throw protocolError(`the verifier sent a ${reply.key.length}-byte template key, or no sealed key`);
    }
    return reply;
  }

  /** The receipt log's records; an empty `subenvId` or `sandboxIds` means all. */
  async listReceipts(request: pb.ListReceiptsRequest): Promise<LoggedReceipt[]> {
    return (await this.#unary(pb.verifierService.ListReceipts, request)).receipts.map(parseLoggedReceipt);
  }

  /** A sandbox's egress log, its hash checked over its lines. */
  async egressLog(envId: string, sandboxId: SandboxId): Promise<EgressLog> {
    return parseEgressLog(sandboxId, await this.#unary(pb.verifierService.GetEgressLog, { envId, sandboxId }, SandboxNotFound));
  }

  close(): void {
    this.#client.close();
  }

  #unary<Req, Res>(method: ClientMethod<Req, Res>, request: Req, notFound?: typeof ClovellyError): Promise<Res> {
    return unary(this.#client, method, request, { deadline: Date.now() + DEADLINE_MS }).catch((error: unknown) => {
      throw verifierError(error, notFound);
    });
  }
}
