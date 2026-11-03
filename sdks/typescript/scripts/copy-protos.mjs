// Copies the protos the SDK loads at runtime from the repository's proto/ into this
// package's proto/, which is committed so the package is self-contained. Run it with
// `npm run protos` after changing a proto, then commit both.
import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const from = join(here, "..", "..", "..", "proto");
const to = join(here, "..", "proto");

const files = [
  "clovelly/cell/v1/cell.proto",
  "clovelly/control/v1/control.proto",
  "clovelly/verifier/v1/verifier.proto",
  "grpc/health/v1/health.proto",
];

for (const file of files) {
  mkdirSync(dirname(join(to, file)), { recursive: true });
  copyFileSync(join(from, file), join(to, file));
  console.log(`proto/${file}`);
}
