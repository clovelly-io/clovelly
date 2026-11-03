// Templates: a sandbox root (a gzipped tar) uploaded once per sub-environment and encrypted
// by the SDK, so only that sub-environment's cells can open it (SPEC.md "Credentials and
// templates are stored as ciphertext we cannot read"). The customer's verifier issues a
// fresh key for the template's digest with the same key sealed under the sub-environment
// DEK (`SealTemplateKey`); the SDK encrypts with the key and streams the ciphertext and the
// sealed key to the control plane (`PutTemplate`).
//
// The ciphertext format is crates/common/src/template.rs's, byte for byte: one record per
// 1 MiB of plaintext (the last may be shorter; an empty template is one empty chunk; a
// template that is a whole number of chunks marks its last full chunk), each a 4-byte
// big-endian length and then AES-256-GCM of the chunk (ciphertext and 16-byte tag) with
// nonce `0^4 || index (u64 BE)` and associated data `"clovelly-v1 template chunk" || digest
// (32 bytes) || index (u64 BE) || last (one byte)`.
import { createCipheriv, createHash } from "node:crypto";
import { type FileHandle, open } from "node:fs/promises";
import { invalidRequest, protocolError } from "./errors.js";
import type * as pb from "./proto.js";

/** Plaintext bytes per chunk. */
export const CHUNK_BYTES = 1 << 20;
/**
 * Ciphertext bytes per PutTemplate data message: 4 MiB less room for the message's own
 * framing, so each message stays within gRPC's default 4 MiB limit on what a server takes.
 */
export const DATA_BYTES = (4 << 20) - 64;
const KEY_BYTES = 32;
const AAD = Buffer.from("clovelly-v1 template chunk", "ascii");

declare const templateDigestBrand: unique symbol;

/** SHA-256 of a template's plaintext: 64 lowercase hex characters. Made only by `isTemplateDigest`. */
export type TemplateDigest = string & { readonly [templateDigestBrand]: true };

/** True for 64 lowercase hex characters. */
export function isTemplateDigest(value: string): value is TemplateDigest {
  return /^[0-9a-f]{64}$/.test(value);
}

/** True for a template name: 1-64 of a-z, 0-9, '_', '-', '.'. */
export function isTemplateName(value: string): boolean {
  return /^[a-z0-9_.-]{1,64}$/.test(value);
}

/**
 * A sub-environment's template, as the control plane stores it. `digest` is what
 * `CreateSandbox` and the sandbox's receipt name. Pass a Template, or its digest, as
 * `env.sandbox(subenv, { template })`.
 */
export interface Template {
  readonly name: string;
  readonly digest: TemplateDigest;
  readonly ciphertextBytes: number;
  readonly plaintextBytes: number;
  /** Stored ciphertext objects (64 MiB each, the last shorter). */
  readonly parts: number;
}

/** Checks a template the control plane described; `ProtocolError` if it is malformed. */
export function parseTemplate(info: pb.TemplateInfo | null): Template {
  if (info === null) throw protocolError("the control plane sent no template");
  const { name, digest, ciphertextBytes, plaintextBytes, parts } = info;
  if (!isTemplateName(name) || !isTemplateDigest(digest)) {
    throw protocolError(`the control plane sent a bad template: name ${JSON.stringify(name)}, digest ${JSON.stringify(digest)}`);
  }
  return { name, digest, ciphertextBytes, plaintextBytes, parts };
}

/** Reads up to one chunk, stopping short only at the end of the file. */
async function readChunk(file: FileHandle): Promise<Buffer> {
  const buffer = Buffer.allocUnsafe(CHUNK_BYTES);
  let filled = 0;
  while (filled < CHUNK_BYTES) {
    const { bytesRead } = await file.read(buffer, filled, CHUNK_BYTES - filled, null);
    if (bytesRead === 0) break;
    filled += bytesRead;
  }
  return buffer.subarray(0, filled);
}

/** The file at `path` in 1 MiB pieces; an empty file is one empty piece. */
async function* chunks(path: string): AsyncGenerator<Buffer> {
  const file = await open(path, "r");
  try {
    for (let first = true; ; first = false) {
      const chunk = await readChunk(file);
      if (chunk.length > 0 || first) yield chunk;
      if (chunk.length < CHUNK_BYTES) return;
    }
  } finally {
    await file.close();
  }
}

/** The SHA-256 of the file at `path` and its size, read 1 MiB at a time. */
export async function fileDigest(path: string): Promise<{ digest: Buffer; size: number }> {
  const hash = createHash("sha256");
  let size = 0;
  for await (const chunk of chunks(path)) {
    hash.update(chunk);
    size += chunk.length;
  }
  return { digest: hash.digest(), size };
}

function u64(value: number): Buffer {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(BigInt(value));
  return bytes;
}

/** One record: the length, then AES-256-GCM of the chunk and its tag. */
function seal(key: Buffer, digest: Buffer, index: number, chunk: Buffer, last: boolean): Buffer {
  const counter = u64(index);
  const cipher = createCipheriv("aes-256-gcm", key, Buffer.concat([Buffer.alloc(4), counter]));
  cipher.setAAD(Buffer.concat([AAD, digest, counter, Buffer.of(last ? 1 : 0)]));
  const body = Buffer.concat([cipher.update(chunk), cipher.final(), cipher.getAuthTag()]);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(body.length);
  return Buffer.concat([length, body]);
}

/**
 * Encrypts a template given as its plaintext chunks (1 MiB each but the last), yielding one
 * record per chunk. `digest` is the plaintext's raw 32-byte SHA-256. Each chunk is sealed
 * once the next has arrived, so the last one is known; no chunks is one empty chunk.
 */
export async function* encrypt(key: Buffer, digest: Buffer, plain: AsyncIterable<Buffer>): AsyncGenerator<Buffer> {
  if (key.length !== KEY_BYTES || digest.length !== 32) throw invalidRequest("a template key and digest are 32 bytes each");
  let index = 0;
  let current: Buffer | undefined;
  for await (const chunk of plain) {
    if (current !== undefined) yield seal(key, digest, index++, current, false);
    current = chunk;
  }
  yield seal(key, digest, index, current ?? Buffer.alloc(0), true);
}

/** The concatenation of `records` cut into pieces of `size` bytes, the last shorter: PutTemplate's data. */
export async function* pieces(records: AsyncIterable<Buffer>, size = DATA_BYTES): AsyncGenerator<Buffer> {
  let pending: Buffer[] = [];
  let length = 0;
  for await (const record of records) {
    pending.push(record);
    length += record.length;
    while (length >= size) {
      const joined = Buffer.concat(pending, length);
      yield joined.subarray(0, size);
      pending = [joined.subarray(size)];
      length -= size;
    }
  }
  if (length > 0) yield Buffer.concat(pending, length);
}

/**
 * The file at `path` encrypted, in data-message pieces, read 1 MiB at a time. `digest` and
 * `size` are what `fileDigest` found; if the file no longer has them, this throws
 * `InvalidRequest` before the last chunk is sealed, so the upload is cancelled rather than
 * finished with a template that does not match its digest.
 */
export function ciphertext(path: string, key: Buffer, digest: Buffer, size: number): AsyncGenerator<Buffer> {
  async function* checked(): AsyncGenerator<Buffer> {
    const hash = createHash("sha256");
    let read = 0;
    for await (const chunk of chunks(path)) {
      hash.update(chunk);
      read += chunk.length;
      if (read > size) break;
      yield chunk;
    }
    if (read !== size || !hash.digest().equals(digest)) {
      throw invalidRequest(`template file ${path} changed while it was being uploaded`);
    }
  }
  return pieces(encrypt(key, digest, checked()));
}
