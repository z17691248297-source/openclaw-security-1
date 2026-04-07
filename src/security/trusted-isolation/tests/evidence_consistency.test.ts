import { expect, test } from "vitest";
import {
  createTrustedIsolationHarness,
  readTrustedEvidenceSummary,
  reserveTrustedIsolationPort,
  runExecThroughTrustedIsolation,
  startStandaloneTrustedBackend,
  writeTrustedIsolationConfig,
} from "../../../../scripts/lib/trusted-isolation/harness.ts";
import { cleanupTrustedIsolationTest } from "./helpers.ts";

test("evidence validator checks pairing and hash continuity", async () => {
  const hmacKey = "dev-trusted-hmac-secret";
  const harness = await createTrustedIsolationHarness({ name: "evidence-consistency" });
  const backend = await startStandaloneTrustedBackend({
    harness,
    port: await reserveTrustedIsolationPort(),
    hmacKey,
  });

  try {
    await writeTrustedIsolationConfig({
      harness,
      enabled: true,
      backendBaseUrl: backend.baseUrl,
      hmacKey,
    });

    const allowExecution = await runExecThroughTrustedIsolation({
      harness,
      command: "echo consistency-pass",
      runId: "run-evidence-allow",
      toolCallId: "tc-evidence-allow",
    });
    expect(allowExecution.hook.blocked).toBe(false);
    expect(allowExecution.error).toBeUndefined();

    const violationExecution = await runExecThroughTrustedIsolation({
      harness,
      command: "echo original",
      runId: "run-evidence-violation",
      toolCallId: "tc-evidence-violation",
      tamperedCommand: "echo tampered",
    });
    expect(violationExecution.error?.message).toContain("trusted scope violation");

    const evidenceSummary = await readTrustedEvidenceSummary(harness.evidencePath);
    expect(evidenceSummary.ok).toBe(true);
    expect(evidenceSummary.summary.authorizePairs).toBeGreaterThanOrEqual(1);
  } finally {
    await cleanupTrustedIsolationTest({ harness, backend });
  }
});
