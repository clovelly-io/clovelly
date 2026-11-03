// Templates: the SDK's ciphertext is crates/common's byte for byte, uploads stream it to the
// control plane under a key from the customer's verifier, and sandboxes name a template and a
// volume.
import assert from "node:assert/strict";
import { createDecipheriv, createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";
import { clovellyError, ClovellyError, ControlPlaneUnavailable } from "../src/errors.js";
import { Environment, InvalidRequest, NoSuchTemplate, TemplateUnavailable, VolumeBusy } from "../src/index.js";
import * as template from "../src/template.js";
import { FakeCell, FakeControl, FakeVerifier, makePki, refusal, VERIFIER_TOKEN } from "./fakes.js";

const CHUNK = 1 << 20;
const KEY = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const pki = makePki();
const dir = mkdtempSync(join(tmpdir(), "clovelly-sdk-template-"));
let files = 0;

/** Byte i is i % 251, as in the Rust vector and crates/common's own tests. */
function pattern(length: number): Buffer {
  return Buffer.from(Array.from({ length }, (_, i) => i % 251));
}

function file(data: Buffer): string {
  const path = join(dir, `template-${files++}.tar.gz`);
  writeFileSync(path, data);
  return path;
}

async function collect(pieces: AsyncIterable<Buffer>): Promise<Buffer[]> {
  const out: Buffer[] = [];
  for await (const piece of pieces) out.push(piece);
  return out;
}

const sha256 = (data: Buffer) => createHash("sha256").update(data).digest();

/**
 * The cell's side of the format (crates/common/src/template.rs `Decryptor`), for checking
 * what was uploaded: every record must open in order, the last-chunk flag set on the final
 * record only.
 */
function decrypt(key: Buffer, digest: Buffer, ciphertext: Buffer): Buffer {
  const plain: Buffer[] = [];
  for (let offset = 0, index = 0; offset < ciphertext.length; index++) {
    const length = ciphertext.readUInt32BE(offset);
    const record = ciphertext.subarray(offset + 4, offset + 4 + length);
    offset += 4 + length;
    const counter = Buffer.alloc(8);
    counter.writeBigUInt64BE(BigInt(index));
    const decipher = createDecipheriv("aes-256-gcm", key, Buffer.concat([Buffer.alloc(4), counter]));
    decipher.setAAD(Buffer.concat([Buffer.from("clovelly-v1 template chunk"), digest, counter, Buffer.of(offset === ciphertext.length ? 1 : 0)]));
    decipher.setAuthTag(record.subarray(record.length - 16));
    plain.push(decipher.update(record.subarray(0, record.length - 16)), decipher.final());
  }
  return Buffer.concat(plain);
}

after(() => rmSync(dir, { recursive: true, force: true }));

describe("template encryption", () => {
  // From crates/common/src/template.rs: a throwaway Rust binary (outside the repo, depending
  // on `common` by path) called common::template::encrypt with key bytes 0..31 on these
  // plaintexts and printed the SHA-256 of each ciphertext. The Python SDK's test checks the
  // same constants.
  const DIGEST = "b5c324a19845fd0e5fd3bb9471d9ced2215154672c50aca851fc0ca780f761da"; // of 1 MiB + 5
  const VECTORS: [plaintext: number, ciphertext: number, sha256: string][] = [
    [CHUNK + 5, 1_048_621, "a6540cd98420766b207786d85e28d0741e36185899a154414c2e1d64ff891572"],
    [CHUNK, 1_048_596, "df0ee53b9d7a5914524b1f9502c11ddf3416de7f14e696773dd6bb44b9143412"],
    [0, 20, "8bb1a4e9df0fcbab4478cef0213e48978b5996978fe6fd2167bde585a541d1fb"],
  ];

  it("is byte for byte the Rust encryptor's", async () => {
    for (const [length, ctBytes, ctSha256] of VECTORS) {
      const path = file(pattern(length));
      const { digest, size } = await template.fileDigest(path);
      assert.equal(size, length);
      if (length === CHUNK + 5) assert.equal(digest.toString("hex"), DIGEST);
      const ct = Buffer.concat(await collect(template.ciphertext(path, KEY, digest, size)));
      assert.deepEqual([ct.length, sha256(ct).toString("hex")], [ctBytes, ctSha256], `plaintext of ${length} bytes`);
      assert.ok(decrypt(KEY, digest, ct).equals(pattern(length)));
    }
  });

  it("refuses a file that changed after its digest, before its last chunk", async () => {
    const path = file(pattern(2 * CHUNK));
    const { digest, size } = await template.fileDigest(path);
    writeFileSync(path, Buffer.concat([pattern(2 * CHUNK - 1), Buffer.from("!")]));
    await assert.rejects(collect(template.ciphertext(path, KEY, digest, size)), /changed while it was being uploaded/);
  });
});

describe("templates and volumes", () => {
  let control: FakeControl;
  let verifier: FakeVerifier;
  let cell: FakeCell;
  let env: Environment;

  before(async () => {
    control = await FakeControl.start(pki.control);
    verifier = await FakeVerifier.start(pki.control);
    cell = await FakeCell.start(pki.cellA);
    control.cells = [{ id: "cell-1", address: cell.address }];
    env = new Environment({
      verifierUrl: verifier.url,
      verifierToken: VERIFIER_TOKEN,
      verifierCa: pki.ca,
      envId: "staging",
      caBundle: pki.ca,
      apiUrl: control.address,
      apiToken: "test-token",
      apiCa: pki.ca,
    });
  });

  after(() => {
    env.close();
    for (const server of [control, verifier, cell]) server.stop();
    rmSync(pki.dir, { recursive: true, force: true });
  });

  it("uploads the header, then ciphertext that opens, in messages under 4 MiB", async () => {
    const plain = pattern(9 * CHUNK + 3); // three data messages
    const digest = sha256(plain);
    const hex = digest.toString("hex");

    const tpl = await env.uploadTemplate("a", "analyst-v3", file(plain));

    assert.deepEqual(verifier.requests.at(-1), { method: "SealTemplateKey", request: { envId: "staging", subenvId: "a", digest: hex } });
    const upload = control.uploads.at(-1);
    assert.ok(upload !== undefined);
    assert.deepEqual(upload.header, {
      envId: "staging",
      subenvId: "a",
      name: "analyst-v3",
      digest: hex,
      sealedKey: Buffer.from(`sealed:${hex}`),
      plaintextBytes: plain.length,
    });
    assert.deepEqual(upload.data.slice(0, -1).map((piece) => piece.length), [template.DATA_BYTES, template.DATA_BYTES]);
    assert.ok((upload.data.at(-1)?.length ?? 0) <= template.DATA_BYTES);
    const ct = Buffer.concat(upload.data);
    assert.equal(ct.length, plain.length + 10 * 20, "a 20-byte length and tag per 1 MiB chunk");
    assert.ok(!ct.includes(plain.subarray(0, 64)), "the control plane receives no plaintext");
    assert.ok(decrypt(FakeVerifier.KEY, digest, ct).equals(plain));
    assert.deepEqual(tpl, { name: "analyst-v3", digest: hex, ciphertextBytes: ct.length, plaintextBytes: plain.length, parts: 1 });
    assert.deepEqual(await env.template("a", "analyst-v3"), tpl);
  });

  it("cancels an upload whose file changed mid-way and stores nothing", async () => {
    const path = file(pattern(CHUNK + 1));
    const uploads = control.uploads.length;
    // SealTemplateKey comes between the digest read and the encrypting read.
    verifier.onSeal = () => writeFileSync(path, pattern(CHUNK + 2).subarray(1));
    try {
      await assert.rejects(env.uploadTemplate("a", "changing", path), (error: unknown) => {
        assert.ok(error instanceof InvalidRequest, String(error));
        assert.match(error.message, /changed while it was being uploaded/);
        return true;
      });
    } finally {
      verifier.onSeal = undefined;
    }
    assert.equal(control.uploads.length, uploads + 1, "the header went out");
    assert.equal(control.templates.has("a/changing"), false, "a cancelled stream stores nothing");
  });

  it("checks template names and types the lookups", async () => {
    const requests = verifier.requests.length;
    for (const bad of ["Analyst", "a b", "x".repeat(65), ""]) {
      await assert.rejects(env.uploadTemplate("a", bad, file(Buffer.from("x"))), InvalidRequest);
    }
    assert.equal(verifier.requests.length, requests, "nothing reaches the verifier");
    await assert.rejects(env.template("a", "missing"), NoSuchTemplate);
  });

  it("creates sandboxes with the template digest and volume", async () => {
    const tpl = await env.uploadTemplate("a", "base", file(Buffer.from("a root")));
    const bare = await env.sandbox("a");
    const byValue = await env.sandbox("a", { template: tpl, volume: "work", volumeGib: 5 });
    const byDigest = await env.sandbox("a", { template: tpl.digest, volume: "work" });
    const lookups = control.calls.filter((call) => call === "GetTemplate").length;
    const byName = await env.sandbox("a", { template: "base" });

    const created = [bare, byValue, byDigest, byName].map((sb) => cell.sandboxes.get(sb.id)?.request);
    assert.deepEqual(
      created.map((request) => [request?.templateDigest, request?.volume, request?.volumeGib]),
      [
        ["", "", 0],
        [tpl.digest, "work", 5],
        [tpl.digest, "work", 0],
        [tpl.digest, "", 0],
      ],
    );
    assert.equal(control.calls.filter((call) => call === "GetTemplate").length, lookups + 1, "only a name is looked up");
    const receipt = await byValue.close();
    assert.deepEqual(receipt.doc.sandbox, { id: byValue.id, template_digest: tpl.digest, volume_id: "work" });
  });

  it("refuses an unknown template name before placing", async () => {
    const places = control.placeRequests.length;
    await assert.rejects(env.sandbox("a", { template: "missing" }), NoSuchTemplate);
    assert.equal(control.placeRequests.length, places);
  });

  it("raises a cell's VOLUME_BUSY without placing again", async () => {
    cell.refuseCreate = refusal("VOLUME_BUSY", grpc.status.FAILED_PRECONDITION);
    const places = control.placeRequests.length;
    try {
      await assert.rejects(env.sandbox("a", { volume: "work" }), (error: unknown) => {
        assert.ok(error instanceof VolumeBusy, String(error));
        assert.equal(error.reason, "VOLUME_BUSY");
        return true;
      });
    } finally {
      cell.refuseCreate = undefined;
    }
    assert.equal(control.placeRequests.length - places, 1);
  });
});

describe("error reasons", () => {
  /** A failed call as grpc-js reports it, refused with `reason`. */
  const failed = (reason: string) => {
    const metadata = new grpc.Metadata();
    metadata.set("clovelly-error", reason);
    return clovellyError(Object.assign(new Error(reason), { code: grpc.status.UNKNOWN, details: reason, metadata }), ControlPlaneUnavailable);
  };

  it("gives every reason in the bundled protos its own class", () => {
    const protos = protoLoader.loadSync(["clovelly/cell/v1/cell.proto", "clovelly/control/v1/control.proto"], {
      includeDirs: [fileURLToPath(new URL("../../proto/", import.meta.url))],
    });
    const isEnum = (definition: protoLoader.AnyDefinition | undefined): definition is protoLoader.EnumTypeDefinition =>
      definition?.format === "Protocol Buffer 3 EnumDescriptorProto";
    const names = ["clovelly.cell.v1.ErrorReason", "clovelly.control.v1.ErrorReason"].flatMap((enumName) => {
      const definition = protos[enumName];
      assert.ok(isEnum(definition), enumName);
      // proto-loader types an enum's descriptor as `object`; it is an EnumDescriptorProto.
      const { value } = definition.type as { value: { name: string }[] };
      return value.map(({ name }) => name).filter((name) => name !== "ERROR_REASON_UNSPECIFIED");
    });
    for (const reason of names) {
      const error = failed(reason);
      assert.ok(error instanceof ClovellyError && error.constructor !== ClovellyError, `${reason} has its own class`);
    }
    assert.ok(failed("TEMPLATE_UNAVAILABLE") instanceof TemplateUnavailable);
    assert.ok(failed("VOLUME_BUSY") instanceof VolumeBusy);
    assert.ok(failed("NO_SUCH_TEMPLATE") instanceof NoSuchTemplate);
  });
});
