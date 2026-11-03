// Receipts: the customer's receipt log at their verifier, and the egress log checked against
// its own hash and a receipt's.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { rmSync } from "node:fs";
import { after, before, beforeEach, describe, it } from "node:test";
import {
  EgressLogMismatch,
  Environment,
  InvalidRequest,
  SandboxNotFound,
  Unauthenticated,
  egressLogSha256,
} from "../src/index.js";
import type * as pb from "../src/proto.js";
import { FakeVerifier, makePki, SIGNATURE, VERIFIER_TOKEN } from "./fakes.js";

const pki = makePki();
const LINES = [
  '{"host":"api.openai.com","port":443,"kind":"substituted"}',
  '{"host":"example.com","port":443,"kind":"wildcard"}',
];
const LINES_SHA256 = createHash("sha256").update(LINES.map((line) => `${line}\n`).join("")).digest("hex");
const [ONE, TWO, THREE] = ["1", "2", "3"].map((digit) => digit.repeat(32)) as [string, string, string];

/** A final record of the receipt log, as the verifier stores it. */
function logged(sandboxId: string, { subenv = "a", egressLogHash = LINES_SHA256 as string | null } = {}): pb.LoggedReceipt {
  const doc = { v: 1, env: "staging", subenv, sandbox: { id: sandboxId }, egress_log_hash: egressLogHash };
  return {
    receipt: Buffer.from(JSON.stringify(doc)),
    signature: SIGNATURE,
    cellCert: Buffer.from("cell certificate"),
    final: true,
    receivedUnixMs: 1_761_000_000_000,
    records: 4,
    finals: 1,
  };
}

describe("the receipt log", () => {
  let verifier: FakeVerifier;
  let env: Environment;
  const envs: Environment[] = [];

  const environment = (verifierToken: string | undefined) => {
    const made = new Environment({ verifierUrl: verifier.url, verifierToken, verifierCa: pki.ca, envId: "staging", caBundle: pki.ca });
    envs.push(made);
    return made;
  };

  before(async () => {
    verifier = await FakeVerifier.start(pki.control);
    env = environment(VERIFIER_TOKEN);
  });

  beforeEach(() => {
    verifier.log = [logged(ONE), logged(TWO), logged(THREE, { subenv: "b", egressLogHash: "0".repeat(64) })];
    verifier.egress.clear();
  });

  after(() => {
    for (const made of envs) made.close();
    verifier.stop();
    rmSync(pki.dir, { recursive: true, force: true });
  });

  it("lists the log's records as asked", async () => {
    const everything = await env.receipts();
    const mine = await env.receipts({ subenv: "a", sandboxIds: [TWO] });

    assert.deepEqual(everything.map(({ doc }) => doc.sandbox), [{ id: ONE }, { id: TWO }, { id: THREE }]);
    assert.deepEqual(verifier.requests.at(-1), { method: "ListReceipts", request: { envId: "staging", subenvId: "a", sandboxIds: [TWO] } });
    const [record] = mine;
    assert.ok(mine.length === 1 && record !== undefined);
    assert.deepEqual([record.final, record.receivedUnixMs, record.records, record.finals], [true, 1_761_000_000_000, 4, 1]);
    assert.ok(record.signature.equals(SIGNATURE) && record.cellCert.equals(Buffer.from("cell certificate")));
    assert.deepEqual(JSON.parse(record.json.toString()), record.doc);
    await assert.rejects(env.receipts({ sandboxIds: ["not-an-id"] }));
  });

  it("checks an egress log against its hash and a receipt's", async () => {
    verifier.egress.set(ONE, { lines: LINES, sha256: LINES_SHA256 });
    const log = await env.egressLog(ONE);
    const [own, other] = await env.receipts({ sandboxIds: [ONE, TWO] });

    assert.deepEqual([log.sandboxId, log.lines, log.sha256], [ONE, LINES, LINES_SHA256]);
    assert.equal(egressLogSha256(LINES), LINES_SHA256);
    assert.ok(own !== undefined && other !== undefined);
    assert.equal(log.matches(own), true);
    assert.equal(log.matches(other), false, "another sandbox's receipt");
    assert.equal(log.matches({ doc: { sandbox: { id: ONE }, egress_log_hash: "0".repeat(64) } }), false, "another hash");
    assert.equal(log.matches({ doc: { sandbox: { id: ONE }, egress_log_hash: null } }), false, "no hash, but lines");

    verifier.egress.set(TWO, { lines: [], sha256: egressLogSha256([]) });
    const empty = await env.egressLog(TWO);
    assert.equal(empty.matches({ doc: { sandbox: { id: TWO }, egress_log_hash: null } }), true, "no egress, empty log");
  });

  it("refuses an egress log that does not hash to its sha256", async () => {
    for (const [lines, sha256] of [
      [[...LINES, '{"host":"exfil.example","port":443}'], LINES_SHA256], // a line added
      [LINES.slice(0, 1), LINES_SHA256], // a line dropped
      [LINES, "0".repeat(64)], // the hash replaced
    ] as const) {
      verifier.egress.set(ONE, { lines, sha256 });
      await assert.rejects(env.egressLog(ONE), EgressLogMismatch);
    }
    await assert.rejects(env.egressLog(TWO), SandboxNotFound);
    await assert.rejects(env.egressLog("not-an-id"));
  });

  it("needs the SDK token", async () => {
    await assert.rejects(environment(undefined).receipts(), (error: unknown) => {
      assert.ok(error instanceof InvalidRequest);
      assert.match(error.message, /SDK token/);
      return true;
    });
    await assert.rejects(environment("wrong").egressLog(ONE), Unauthenticated);
  });
});
