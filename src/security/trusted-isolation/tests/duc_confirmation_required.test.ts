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

test("duc decisions block on trusted confirmation and record authorize plus deny evidence", async () => {
  const hmacKey = "dev-trusted-hmac-secret";
  const harness = await createTrustedIsolationHarness({ name: "duc-confirmation-required" });
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
      command: "tar -czf workspace.tgz docs",
      runId: "run-duc-confirmation-required",
      toolCallId: "tc-duc-confirmation-required",
    });

    expect(execution.hook.blocked).toBe(true);
    if (execution.hook.blocked) {
      expect(execution.hook.reason).toContain("confirmation");
      expect(execution.hook.reason).toContain("/approve trusted:");
    }

    const evidenceRecords = await readJsonlRecords(harness.evidencePath);
    const eventsByReqId = groupEvidenceByReqId(evidenceRecords);
    const ducReqId = [...eventsByReqId.entries()].find(([, events]) => {
      return events.includes("authorize") && events.includes("deny");
    })?.[0];

    expect(ducReqId).toBeTruthy();
    const ducRecords = evidenceRecords.filter((entry) => entry.reqId === ducReqId);
    expect(ducRecords).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          event: "authorize",
          decision: "duc",
          executionMode: "ree-constrained",
        }),
        expect.objectContaining({
          event: "deny",
          decision: "duc",
          status: "confirmation_required",
          confirmationStatus: "pending",
        }),
      ]),
    );
  } finally {
    await cleanupTrustedIsolationTest({ harness, backend });
  }
});
