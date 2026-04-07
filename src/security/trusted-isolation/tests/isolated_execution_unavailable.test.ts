import { expect, test } from "vitest";
import {
  createTrustedIsolationHarness,
  readJsonlRecords,
  reserveTrustedIsolationPort,
  runExecThroughTrustedIsolation,
  startStandaloneTrustedBackend,
  writeTrustedIsolationConfig,
} from "../../../../scripts/lib/trusted-isolation/harness.ts";
import { cleanupTrustedIsolationTest, groupEvidenceByReqId } from "./helpers.ts";

test("die decisions fail closed when no isolated executor is available", async () => {
  const hmacKey = "dev-trusted-hmac-secret";
  const harness = await createTrustedIsolationHarness({ name: "isolated-unavailable" });
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

    const execution = await runExecThroughTrustedIsolation({
      harness,
      command: "if [ -f README.md ]; then sed -n '1,20p' README.md; else echo '__NO_README__'; fi",
      runId: "run-isolated-unavailable",
      toolCallId: "tc-isolated-unavailable",
    });

    expect(execution.hook.blocked).toBe(true);
    if (execution.hook.blocked) {
      expect(execution.hook.reason).toContain("trusted isolated execution unavailable");
    }

    const evidenceRecords = await readJsonlRecords(harness.evidencePath);
    const eventsByReqId = groupEvidenceByReqId(evidenceRecords);
    const isolatedReqId = [...eventsByReqId.entries()].find(([, events]) => {
      return events.includes("authorize") && events.includes("complete");
    })?.[0];

    expect(isolatedReqId).toBeTruthy();
    const isolatedRecords = evidenceRecords.filter((entry) => entry.reqId === isolatedReqId);
    expect(isolatedRecords).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          event: "authorize",
          decision: "die",
          executionMode: "isolated",
        }),
        expect.objectContaining({
          event: "complete",
          decision: "die",
          executionMode: "isolated",
          status: "trusted_isolated_execution_unavailable",
          errorCode: "trusted_isolated_execution_unavailable",
        }),
      ]),
    );
  } finally {
    await cleanupTrustedIsolationTest({ harness, backend });
  }
});
