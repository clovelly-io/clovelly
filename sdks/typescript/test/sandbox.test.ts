// The sandbox flow against a fake control plane and fake cells: criteria 1, 9 (typed
// refusals and re-placement), 12 (one connection, 50 sandboxes' streams) and 13 (reconnect).
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { rmSync } from "node:fs";
import { after, before, beforeEach, describe, it } from "node:test";
import * as grpc from "@grpc/grpc-js";
import {
  AbovePolicyMaximum,
  QuotaExceeded,
  CreditExhausted,
  CapacityError,
  CellVerificationError,
  Environment,
  type EnvironmentOptions,
  InvalidRequest,
  PermissionDenied,
  ProtocolError,
  placeholder,
} from "../src/index.js";
import { FakeCell, FakeControl, makePki, refusal, SIGNATURE } from "./fakes.js";

const pki = makePki();

describe("sandboxes", () => {
  let control: FakeControl;
  let first: FakeCell;
  let second: FakeCell;
  let untrusted: FakeCell;
  const envs: Environment[] = [];

  /** An environment on the fake control plane; closed after the suite. */
  const environment = (options: Partial<EnvironmentOptions> = {}) => {
    const env = new Environment({
      verifierUrl: "https://verifier.test",
      envId: "staging",
      caBundle: pki.ca,
      apiUrl: `https://${control.address}`,
      apiToken: "test-token",
      apiCa: pki.ca,
      ...options,
    });
    envs.push(env);
    return env;
  };

  before(async () => {
    control = await FakeControl.start(pki.control);
    first = await FakeCell.start(pki.cellA);
    second = await FakeCell.start(pki.cellA);
    untrusted = await FakeCell.start(pki.selfSigned);
  });

  beforeEach(() => {
    control.cells = [
      { id: "cell-1", address: first.address },
      { id: "cell-2", address: second.address },
    ];
    control.refusePlace = undefined;
    control.tamper = undefined;
    first.refuseCreate = undefined;
    second.refuseCreate = undefined;
  });

  after(() => {
    for (const env of envs) env.close();
    for (const server of [control, first, second, untrusted]) server.stop();
    rmSync(pki.dir, { recursive: true, force: true });
  });

  it("creates a sandbox, runs code, writes and reads a file, and closes it", async () => {
    const env = environment();
    const sb = await env.sandbox("a", { cpu: 1, memory: 2, timeout: 600 });

    assert.match(sb.id, /^[0-9a-f]{32}$/);
    assert.match(sb.key, /^[0-9a-f]{64}$/);
    assert.equal(sb.cellId, "cell-1");
    assert.equal(sb.cellAddress, first.address);
    assert.deepEqual([sb.subenv, sb.cold, sb.cpu, sb.memory, sb.timeout], ["a", false, 1, 2, 600]);
    assert.ok(sb.timings.connectMs > 0);
    assert.equal(sb.timings.runscMs, 7);
    assert.deepEqual(control.placeRequests.at(-1), {
      envId: "staging",
      subenvId: "a",
      size: { cpuHalves: 2, memoryGib: 2 },
      timeoutSecs: 600,
      avoidCells: [],
    });
    assert.ok(control.authorizations.length > 0);
    assert.ok(control.authorizations.every((value) => value === "Bearer test-token"));
    const onCell = first.sandboxes.get(sb.id);
    assert.equal(onCell?.key.toString("hex"), sb.key);
    assert.deepEqual([onCell.cpuHalves, onCell.memoryGib, onCell.timeoutSecs], [2, 2, 600]);

    const python = await sb.exec("python3 -c 'print(6*7)'");
    assert.equal(python.exitCode, 0);
    assert.equal(python.stdout.toString(), "42\n");
    assert.equal(python.firstExecMs, 5);
    assert.equal(typeof python.firstStdoutAt, "number");
    assert.equal(python.sandboxEnded, undefined);

    const stdin = randomBytes(200 * 1024);
    const cat = await sb.exec(["cat"], { stdin });
    assert.ok(cat.stdout.equals(stdin));
    assert.equal(cat.stderr.toString(), '["cat"]');
    assert.equal(cat.firstExecMs, undefined);
    assert.deepEqual(onCell.stdinChunks.at(-1), [65536, 65536, 65536, 8192]);

    const data = randomBytes(100 * 1024);
    await sb.files.write("/work/input.bin", data);
    assert.ok((await sb.files.read("/work/input.bin")).equals(data));

    const interim = await sb.receipt();
    assert.deepEqual([interim.exitKind, interim.final], ["running", false]);
    const receipt = await sb.close();
    assert.deepEqual([receipt.exitKind, receipt.final], ["killed", true]);
    assert.deepEqual(receipt.doc.sandbox, { id: sb.id, template_digest: null, volume_id: null });
    assert.deepEqual(JSON.parse(receipt.json.toString()), receipt.doc);
    assert.equal(receipt.data, receipt.doc, "data is doc's name before phase 4");
    assert.ok(receipt.signature.equals(SIGNATURE));
    assert.ok(receipt.cellCert.equals(first.cert), "the cell's DER certificate");
    assert.deepEqual(control.released, [sb.id]);
    const again = await sb.close();
    assert.equal(again.exitKind, "killed", "closing an ended sandbox returns its receipt");

    const next = await env.sandbox("a");
    assert.equal(next.timings.connectMs, 0, "the second sandbox on a cell reuses its connection");
    assert.deepEqual([next.cpu, next.memory, next.timeout], [1, 2, 900], "zero takes the sub-environment default");
  });

  it("refuses a self-signed cell the control plane placed it on", async () => {
    control.cells = [{ id: "cell-x", address: untrusted.address }];
    await assert.rejects(environment().sandbox("a"), CellVerificationError);
    assert.deepEqual(untrusted.calls, []);
  });

  it("raises the control plane's ABOVE_POLICY_MAXIMUM as AbovePolicyMaximum", async () => {
    control.refusePlace = refusal("ABOVE_POLICY_MAXIMUM", grpc.status.INVALID_ARGUMENT);
    await assert.rejects(environment().sandbox("a", { cpu: 64 }), (error: unknown) => {
      assert.ok(error instanceof AbovePolicyMaximum, String(error));
      assert.equal(error.reason, "ABOVE_POLICY_MAXIMUM");
      assert.equal(error.code, grpc.status.INVALID_ARGUMENT);
      return true;
    });
  });

  it("raises QUOTA_EXCEEDED as QuotaExceeded and does not place again", async () => {
    control.refusePlace = refusal("QUOTA_EXCEEDED", grpc.status.RESOURCE_EXHAUSTED);
    await assert.rejects(environment().sandbox("a"), (error: unknown) => {
      assert.ok(error instanceof QuotaExceeded, String(error));
      assert.equal(error.reason, "QUOTA_EXCEEDED");
      return true;
    });
  });

  it("raises CREDIT_EXHAUSTED as CreditExhausted and does not place again", async () => {
    control.refusePlace = refusal("CREDIT_EXHAUSTED", grpc.status.FAILED_PRECONDITION);
    await assert.rejects(environment().sandbox("a"), (error: unknown) => {
      assert.ok(error instanceof CreditExhausted, String(error));
      assert.equal(error.reason, "CREDIT_EXHAUSTED");
      return true;
    });
  });

  it("places again, avoiding a cell that refuses for CAPACITY", async () => {
    first.refuseCreate = refusal("CAPACITY", grpc.status.RESOURCE_EXHAUSTED);
    const placed = control.placeRequests.length;
    const sb = await environment().sandbox("a");
    assert.equal(sb.cellId, "cell-2");
    assert.ok(second.sandboxes.has(sb.id));
    assert.deepEqual(
      control.placeRequests.slice(placed).map(({ avoidCells }) => avoidCells),
      [[], ["cell-1"]],
    );
  });

  it("gives up with CapacityError after three placements", async () => {
    control.cells = [1, 2, 3].map((n) => ({ id: `cell-${n}`, address: first.address }));
    first.refuseCreate = refusal("CAPACITY", grpc.status.RESOURCE_EXHAUSTED);
    const placed = control.placeRequests.length;
    await assert.rejects(environment().sandbox("a"), CapacityError);
    assert.equal(control.placeRequests.length - placed, 3);
  });

  it("reconnects to the same sandbox from a fresh Environment", async () => {
    const creator = environment();
    const sb = await creator.sandbox("a");
    await sb.files.write("/work/state", "kept");
    creator.close();

    const env = environment({ caBundle: pki.caPath });
    const again = await env.reconnect(sb.id, sb.key);
    assert.deepEqual([again.id, again.cellId, again.cellAddress], [sb.id, sb.cellId, sb.cellAddress]);
    assert.equal((await again.files.read("/work/state")).toString(), "kept");
    await assert.rejects(env.reconnect(sb.id, randomBytes(32).toString("hex")), PermissionDenied);
  });

  it("refuses a placement for another sub-environment than the one asked for", async () => {
    const env = environment();
    const sb = await env.sandbox("a");
    assert.equal((await env.reconnect(sb.id, sb.key, { subenv: "a" })).cellId, sb.cellId);
    await assert.rejects(env.reconnect(sb.id, sb.key, { subenv: "b" }), ProtocolError);

    control.tamper = (placement) => ({ ...placement, subenvId: "b" });
    const creates = first.calls.filter((call) => call === "CreateSandbox").length;
    await assert.rejects(env.sandbox("a"), ProtocolError);
    assert.equal(first.calls.filter((call) => call === "CreateSandbox").length, creates);
  });

  it("releases every placement that does not become a sandbox", async () => {
    const placed = () => [...control.placements.values()];
    const before = placed().length;
    first.refuseCreate = refusal("CAPACITY", grpc.status.RESOURCE_EXHAUSTED);
    const sb = await environment().sandbox("a");
    const [refused] = placed().slice(before);
    assert.equal(refused?.cellId, "cell-1");
    assert.ok(control.released.includes(refused.sandboxId), "the refused placement is released");
    assert.ok(!control.released.includes(sb.id), "the sandbox's own placement is kept");

    control.cells = [{ id: "cell-x", address: untrusted.address }];
    await assert.rejects(environment().sandbox("a"), CellVerificationError);
    assert.equal(control.released.at(-1), placed().at(-1)?.sandboxId, "a placement on a refused cell is released");
  });

  it("checks cpu, template and volume before placing", async () => {
    const env = environment();
    const placed = control.placeRequests.length;
    await assert.rejects(env.sandbox("a", { cpu: 1.25 }), InvalidRequest);
    await assert.rejects(env.sandbox("a", { cpu: 0 }), InvalidRequest);
    // @ts-expect-error a sub-environment has one policy bundle
    await assert.rejects(env.sandbox("a", { policy: "default" }), InvalidRequest);
    for (const options of [
      { template: "Analyst v3" },
      { volume: "a/b" },
      { volume: "v", volumeGib: 21 },
      { volume: "v", volumeGib: 1.5 },
      { volumeGib: 2 },
    ]) {
      await assert.rejects(env.sandbox("a", options), InvalidRequest, JSON.stringify(options));
    }
    assert.equal(control.placeRequests.length, placed, "nothing invalid reaches the control plane");
    const sb = await env.sandbox("a", { cpu: 1.5 });
    assert.equal(control.placeRequests.at(-1)?.size.cpuHalves, 3);
    assert.equal(sb.cpu, 1.5);
  });

  it("multiplexes 50 sandboxes' exec streams over one connection", { timeout: 10_000 }, async () => {
    const env = environment();
    first.peers.clear();
    const sandboxes = await Promise.all(Array.from({ length: 50 }, () => env.sandbox("a")));
    assert.ok(sandboxes.every((sb) => sb.cellId === "cell-1"));
    // Every Exec holds its output until all 50 are open, so this only completes if the
    // streams run concurrently on the shared connection.
    first.holdExecs(50);
    const results = await Promise.all(sandboxes.map((sb, i) => sb.exec(["cat"], { stdin: `sandbox ${i}` })));
    results.forEach(({ stdout }, i) => assert.equal(stdout.toString(), `sandbox ${i}`));
    assert.equal(first.peers.size, 1, "one connection carried every call");
  });
});

describe("credentials", () => {
  it("names placeholders and checks putCredential's arguments before any call", async () => {
    assert.equal(placeholder("openai"), "clovelly://cred/openai");
    assert.throws(() => placeholder("Open AI"), InvalidRequest);
    const env = new Environment({ verifierUrl: "https://verifier.invalid", envId: "staging", caBundle: pki.ca });
    const good = { adapter: "bearer", destination: "api.example.com" } as const;
    for (const [name, secret, opts] of [
      ["Bad Name", "s", good],
      ["ok", "", good],
      ["ok", "s", { adapter: "bearer", destination: "*.example.com" }],
    ] as const) {
      await assert.rejects(env.putCredential("a", name, secret, opts), InvalidRequest);
    }
    await assert.rejects(env.putCredential("a", "ok", "s", good), /SDK token/);
    env.close();
  });
});
