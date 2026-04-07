import path from "node:path";
import { expect, test } from "vitest";
import {
  assertFileMissing,
  createTrustedIsolationHarness,
  readJsonlRecords,
  runExecThroughTrustedIsolation,
  writeTrustedIsolationConfig,
} from "../../../../scripts/lib/trusted-isolation/harness.ts";
import { cleanupTrustedIsolationTest } from "./helpers.ts";

test("backend unavailable fail-closed blocks forced exec and records backend_error evidence", async () => {
  const harness = await createTrustedIsolationHarness({ name: "backend-unavailable" });

  try {
    await writeTrustedIsolationConfig({
      harness,
      enabled: true,
      backendBaseUrl: "http://127.0.0.1:19499",
      hmacKey: "dev-trusted-hmac-secret",
      requestTimeoutMs: 500,
    });

    const execution = await runExecThroughTrustedIsolation({
      harness,
      command: "echo blocked > blocked.txt",
      runId: "run-backend-unavailable",
      toolCallId: "tc-backend-unavailable",
    });

    expect(execution.hook.blocked).toBe(true);
    if (execution.hook.blocked) {
      expect(execution.hook.reason).toContain("trusted backend unavailable");
    }
    await assertFileMissing(path.join(harness.workspaceDir, "blocked.txt"));

    const evidenceRecords = await readJsonlRecords(harness.evidencePath);
    expect(evidenceRecords.some((entry) => entry.event === "backend_error")).toBe(true);
  } finally {
    await cleanupTrustedIsolationTest({ harness });
  }
});
