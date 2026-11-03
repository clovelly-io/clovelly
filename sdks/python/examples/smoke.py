"""Phase 2 criterion 1 from a customer machine: create a sandbox, run Python in it,
write then read a file, close it. Prints one JSON object with each step's result and
timing, and exits non-zero if any step fails.

The SDK is given only the verifier URL, the environment id and the CA bundle, plus the
control plane's address and token:

    CLOVELLY_VERIFIER_URL  the customer's verifier (kept for later phases)
    CLOVELLY_ENV_ID        the environment id
    CLOVELLY_CA_BUNDLE     path to the environment CA (PEM, from the verifier's GetCA)
    CLOVELLY_SUBENV        the sub-environment to create the sandbox in
    CLOVELLY_API_URL, CLOVELLY_API_TOKEN, CLOVELLY_API_CA   the control plane (CA optional)

    python examples/smoke.py
"""

from __future__ import annotations

import json
import os
import secrets
import sys
import time
from typing import Any, Callable, Optional

import clovelly


def main() -> int:
    report: dict[str, Any] = {"ok": False, "steps": {}}
    steps: dict[str, dict[str, Any]] = report["steps"]

    def step(name: str, run: Callable[[], dict[str, Any]]) -> Optional[dict[str, Any]]:
        started = time.perf_counter()
        try:
            result = run()
        except Exception as err:  # the report records every failure, typed
            steps[name] = {
                "ok": False,
                "ms": round((time.perf_counter() - started) * 1000, 2),
                "error": type(err).__name__,
                "reason": getattr(err, "reason", None),
                "detail": str(err),
            }
            return None
        steps[name] = {"ok": True, "ms": round((time.perf_counter() - started) * 1000, 2), **result}
        return result

    required = ("CLOVELLY_VERIFIER_URL", "CLOVELLY_ENV_ID", "CLOVELLY_CA_BUNDLE", "CLOVELLY_SUBENV", "CLOVELLY_API_URL", "CLOVELLY_API_TOKEN")
    missing = [name for name in required if not os.environ.get(name)]
    if missing:
        report["error"] = f"set {', '.join(missing)}"
        return finish(report)

    env = clovelly.Environment(
        os.environ["CLOVELLY_VERIFIER_URL"], os.environ["CLOVELLY_ENV_ID"], os.environ["CLOVELLY_CA_BUNDLE"]
    )
    sandbox: Optional[clovelly.Sandbox] = None
    try:

        def create() -> dict[str, Any]:
            nonlocal sandbox
            sandbox = env.sandbox(os.environ["CLOVELLY_SUBENV"])
            return {
                "sandbox_id": sandbox.id,
                "cell_id": sandbox.cell_id,
                "cell_address": sandbox.cell_address,
                "cold": sandbox.cold,
                "cpu": sandbox.cpu,
                "memory": sandbox.memory,
                "timeout": sandbox.timeout,
                "timings": {k: round(v, 2) for k, v in sandbox.timings.items()},
            }

        if step("create", create) is None or sandbox is None:
            return finish(report)
        sb = sandbox

        def run() -> dict[str, Any]:
            sent = time.perf_counter()
            r = sb.exec("python3 -c 'print(6*7)'")
            if r.exit_code != 0 or r.stdout != b"42\n":
                raise RuntimeError(f"exit {r.exit_code}, stdout {r.stdout!r}, stderr {r.stderr!r}")
            first = round((r.first_stdout_at - sent) * 1000, 2) if r.first_stdout_at else None
            return {"stdout": r.stdout.decode(), "first_exec_ms": r.first_exec_ms, "first_stdout_ms": first}

        marker = f"clovelly-smoke-{secrets.token_hex(8)}\n".encode()
        path = "/tmp/clovelly-smoke.txt"

        def write() -> dict[str, Any]:
            return {"path": path, "bytes": sb.files.write(path, marker)}

        def read() -> dict[str, Any]:
            data = sb.files.read(path)
            if data != marker:
                raise RuntimeError(f"read back {data!r}, wrote {marker!r}")
            return {"bytes": len(data)}

        def close() -> dict[str, Any]:
            receipt = sb.close()
            return {"exit_kind": receipt.exit_kind, "receipt": receipt.doc}

        step("exec", run)
        step("write", write)
        step("read", read)
        step("close", close)
    finally:
        env.close()
    return finish(report)


def finish(report: dict[str, Any]) -> int:
    report["ok"] = bool(report["steps"]) and all(s["ok"] for s in report["steps"].values())
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
