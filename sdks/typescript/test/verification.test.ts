// Phase 2 criterion 2 and phase 12 criterion 9: the SDK refuses a cell that is not verified for
// its environment, sub-environment and own name, with a typed error, and nothing but the TLS
// handshake reaches the cell.
import assert from "node:assert/strict";
import { rmSync } from "node:fs";
import { after, before, describe, it } from "node:test";
import { CellVerificationError, type CellVerificationKind, Environment, InvalidRequest } from "../src/index.js";
import { CELL_1, CELL_2, CELL_B, FakeCell, type KeyPair, makePki } from "./fakes.js";

const pki = makePki();

describe("cell verification", () => {
  // Each is dialled as CELL_1.
  const refusals: [string, KeyPair, CellVerificationKind][] = [
    ["a self-signed certificate", pki.selfSigned, "untrusted_certificate"],
    ["a certificate from another environment's CA", pki.otherCa, "untrusted_certificate"],
    ["a certificate naming another sub-environment", pki.cellB, "name_mismatch"],
    ["a second cell's certificate, behind a relay that routed to the wrong cell", pki.cellA2, "name_mismatch"],
    ["a certificate naming only the sub-environment, as before phase 12", pki.oldA, "name_mismatch"],
  ];
  const cells = new Map<string, FakeCell>();
  const env = new Environment({ verifierUrl: "https://verifier.test", envId: "staging", caBundle: pki.ca });

  before(async () => {
    for (const [name, pair] of refusals) cells.set(name, await FakeCell.start(pair));
    cells.set("verified", await FakeCell.start(pki.cellA2));
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
      const cell = env.cell(fake.address, CELL_1, "a");
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
        assert.equal(error.serverName, CELL_1);
        return true;
      });
      assert.deepEqual(fake.calls, []);
      assert.ok(cell.closed);
      assert.notEqual(env.cell(fake.address, CELL_1, "a"), cell, "a refused cell is dropped from the cache");
    });
  }

  it("accepts a certificate from the environment CA carrying the cell's name", async () => {
    const fake = cells.get("verified");
    assert.ok(fake);
    const cell = env.cell(fake.address, CELL_2, "a");
    await cell.verify();
    assert.ok(cell.verified);
    assert.deepEqual(fake.calls, ["Health/Check"]);
    assert.equal(env.cell(fake.address, CELL_2, "a"), cell, "one cached connection per cell");
    // Every cell of a region shares the relay's address: the cache is per name.
    assert.notEqual(env.cell(fake.address, CELL_1, "a"), cell, "the cache is per cell name");
  });

  it("refuses a name outside the sub-environment before dialling", () => {
    assert.throws(() => env.cell("127.0.0.1:1", CELL_B, "a"), InvalidRequest);
    assert.throws(() => env.cell("127.0.0.1:1", "a.staging.cells.clovelly.internal", "a"), InvalidRequest);
  });
});
