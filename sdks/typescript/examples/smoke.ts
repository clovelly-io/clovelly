// Phase 2 criterion 1 against a real cell: create a sandbox, run Python, write and read a
// file, close. Prints one JSON object with each step's result and time; exits non-zero on
// any failure.
//
//   CLOVELLY_VERIFIER_URL=... CLOVELLY_ENV_ID=staging CLOVELLY_CA_BUNDLE=env-ca.pem CLOVELLY_SUBENV=a \
//   CLOVELLY_API_URL=... CLOVELLY_API_TOKEN=... [CLOVELLY_API_CA=...] [CLOVELLY_SMOKE_FILE=/tmp/clovelly-smoke.txt] \
//   node dist/examples/smoke.js
import { randomBytes } from "node:crypto";
import { ClovellyError, CellVerificationError, Environment, type Sandbox } from "../src/index.js";

interface Report {
  ok: boolean;
  steps: Record<string, Record<string, unknown>>;
  error?: { name: string; message: string; reason?: string | undefined; kind?: string };
}

const report: Report = { ok: false, steps: {} };

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set`);
  return value;
}

/** Runs one step, recording its time and a summary of its result, or that it failed. */
async function step<T>(name: string, work: () => Promise<T>, summary: (value: T) => Record<string, unknown>): Promise<T> {
  const started = performance.now();
  const elapsed = () => round(performance.now() - started);
  try {
    const value = await work();
    report.steps[name] = { ms: elapsed(), ...summary(value) };
    return value;
  } catch (error) {
    report.steps[name] = { ms: elapsed(), failed: true };
    throw error;
  }
}

/** Milliseconds to 0.1. */
function round(ms: number): number {
  return Math.round(ms * 10) / 10;
}

function check(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

let env: Environment | undefined;
let sandbox: Sandbox | undefined;
try {
  const environment = new Environment({
    verifierUrl: required("CLOVELLY_VERIFIER_URL"),
    envId: required("CLOVELLY_ENV_ID"),
    caBundle: required("CLOVELLY_CA_BUNDLE"),
  });
  env = environment;
  const subenv = required("CLOVELLY_SUBENV");
  const file = process.env.CLOVELLY_SMOKE_FILE || "/tmp/clovelly-smoke.txt";

  const sb = await step("create", () => environment.sandbox(subenv), (sb) => ({
    sandboxId: sb.id,
    cellId: sb.cellId,
    cellAddress: sb.cellAddress,
    cold: sb.cold,
    cpu: sb.cpu,
    memory: sb.memory,
    timeout: sb.timeout,
    timings: Object.fromEntries(Object.entries(sb.timings).map(([key, ms]) => [key, round(ms)])),
  }));
  sandbox = sb;

  const result = await step("exec", () => sb.exec("python3 -c 'print(6*7)'"), (r) => ({
    exitCode: r.exitCode,
    stdout: r.stdout.toString(),
    stderr: r.stderr.toString(),
    firstExecMs: r.firstExecMs,
  }));
  check(result.exitCode === 0 && result.stdout.toString() === "42\n", "python3 did not print 42");

  const marker = `clovelly smoke ${randomBytes(8).toString("hex")}\n`;
  await step("write", () => sb.files.write(file, marker), () => ({ path: file, bytes: marker.length }));
  const back = await step("read", () => sb.files.read(file), (data) => ({ path: file, matches: data.toString() === marker }));
  check(back.toString() === marker, `${file} did not read back what was written`);

  sandbox = undefined;
  await step("close", () => sb.close(), (receipt) => ({ exitKind: receipt.exitKind, receipt: receipt.doc }));
  report.ok = true;
} catch (error) {
  report.error =
    error instanceof Error
      ? {
          name: error.name,
          message: error.message,
          ...(error instanceof ClovellyError && { reason: error.reason }),
          ...(error instanceof CellVerificationError && { kind: error.kind }),
        }
      : { name: "Error", message: String(error) };
  // Best effort: do not leave the sandbox running until its timeout.
  await sandbox?.close().catch(() => undefined);
} finally {
  env?.close();
}

console.log(JSON.stringify(report, null, 2));
process.exitCode = report.ok ? 0 : 1;
