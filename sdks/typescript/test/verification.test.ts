// Criterion 2: the SDK refuses a cell that is not verified for its environment and
// sub-environment, with a typed error, and nothing but the TLS handshake reaches the cell.
import assert from "node:assert/strict";
import { rmSync } from "node:fs";
import { after, before, describe, it } from "node:test";
import { CellVerificationError, type CellVerificationKind, Environment } from "../src/index.js";
import { FakeCell, type KeyPair, makePki } from "./fakes.js";

const pki = makePki();

describe("cell verification", () => {
  const refusals: [string, KeyPair, CellVerificationKind][] = [
    ["a self-signed certificate", pki.selfSigned, "untrusted_certificate"],
    ["a certificate from another environment's CA", pki.otherCa, "untrusted_certificate"],
    ["a certificate naming another sub-environment", pki.cellB, "name_mismatch"],
  ];
  const cells = new Map<string, FakeCell>();
  const env = new Environment({ verifierUrl: "https://verifier.test", envId: "staging", caBundle: pki.ca });

  before(async () => {
    for (const [name, pair] of refusals) cells.set(name, await FakeCell.start(pair));
    cells.set("verified", await FakeCell.start(pki.cellA));
  });

  after(() => {
    env.close();
    for (const cell of cells.values()) cell.stop();
    rmSync(pki.dir, { recursive: true, force: true });
  });

  for (const [name, , kind] of refusals) {
    it(`refuses ${name} (${kind}) and sends it nothing`, async () => {
      const fake = cells.get(name);
      assert.ok(fake);
      const cell = env.cell(fake.address, "a");
      const create = cell.createSandbox({
        sandboxId: "0".repeat(32),
        key: Buffer.alloc(32),
        cpuHalves: 2,
        memoryGib: 2,
        timeoutSecs: 60,
      });
      await assert.rejects(create, (error: unknown) => {
        assert.ok(error instanceof CellVerificationError, String(error));
        assert.equal(error.kind, kind);
        assert.equal(error.serverName, "a.staging.cells.clovelly.internal");
        return true;
      });
      assert.deepEqual(fake.calls, []);
      assert.ok(cell.closed);
      assert.notEqual(env.cell(fake.address, "a"), cell, "a refused cell is dropped from the cache");
    });
  }

  it("accepts a certificate from the environment CA naming the sub-environment", async () => {
    const fake = cells.get("verified");
    assert.ok(fake);
    const cell = env.cell(fake.address, "a");
    await cell.verify();
    assert.ok(cell.verified);
    assert.deepEqual(fake.calls, ["Health/Check"]);
    assert.equal(env.cell(fake.address, "a"), cell, "one cached connection per cell");
    assert.notEqual(env.cell(fake.address, "b"), cell, "the cache is per sub-environment name");
  });
});
