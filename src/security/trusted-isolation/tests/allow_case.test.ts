import { expect, test } from "vitest";
import {
  createTrustedIsolationHarness,
  extractToolResultText,
  readJsonlRecords,
  readTrustedEvidenceSummary,
  reserveTrustedIsolationPort,
  runExecThroughTrustedIsolation,
  startStandaloneTrustedBackend,
  writeTrustedIsolationConfig,
} from "../../../../scripts/lib/trusted-isolation/harness.ts";
import { cleanupTrustedIsolationTest, groupEvidenceByReqId } from "./helpers.ts";

test("allow case authorizes exec, executes, and writes paired evidence", async () => {
  const hmacKey = "dev-trusted-hmac-secret";
  const harness = await createTrustedIsolationHarness({ name: "allow-case" });
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
      command: "echo trusted-hi",
      runId: "run-allow",
      toolCallId: "tc-allow",
    });

    expect(execution.hook.blocked).toBe(false);
    expect(execution.error).toBeUndefined();
    expect(extractToolResultText(execution.result)).toContain("trusted-hi");

    const evidenceSummary = await readTrustedEvidenceSummary(harness.evidencePath);
    expect(evidenceSummary.ok).toBe(true);

    const evidenceRecords = await readJsonlRecords(harness.evidencePath);
    const eventsByReqId = groupEvidenceByReqId(evidenceRecords);
    const pairedReqId = [...eventsByReqId.entries()].find(([, events]) => {
      return events.includes("authorize") && events.includes("complete");
    })?.[0];

    expect(pairedReqId).toBeTruthy();
    const pairedRecords = evidenceRecords.filter((entry) => entry.reqId === pairedReqId);
    expect(pairedRecords.every((entry) => entry.action !== "unknown")).toBe(true);
    expect(pairedRecords.every((entry) => entry.object !== "unknown")).toBe(true);
  } finally {
    await cleanupTrustedIsolationTest({ harness, backend });
  }
});
