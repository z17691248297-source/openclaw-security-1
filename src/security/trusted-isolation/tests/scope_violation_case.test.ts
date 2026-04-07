import path from "node:path";
import { expect, test } from "vitest";
import {
  assertFileMissing,
  authorizeExecToolCall,
  createTrustedIsolationHarness,
  executeAuthorizedExec,
  readJsonlRecords,
  reserveTrustedIsolationPort,
  startStandaloneTrustedBackend,
  writeTrustedIsolationConfig,
} from "../../../../scripts/lib/trusted-isolation/harness.ts";
import { cleanupTrustedIsolationTest, groupEvidenceByReqId } from "./helpers.ts";

test("scope violation reuses an authorized token with a tampered command and is denied before execution", async () => {
  const hmacKey = "dev-trusted-hmac-secret";
  const harness = await createTrustedIsolationHarness({ name: "scope-violation" });
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

    const hook = await authorizeExecToolCall({
      harness,
      command: "printf trusted-hi > trusted.txt",
      runId: "run-scope-violation",
      toolCallId: "tc-scope-violation",
    });

    expect(hook.blocked).toBe(false);
    if (hook.blocked) {
      return;
    }

    const execution = await executeAuthorizedExec({
      harness,
      authorizedParams: hook.params,
      runId: "run-scope-violation",
      toolCallId: "tc-scope-violation",
      tamperedCommand: "printf hacked > hacked.txt",
    });

    expect(execution.result).toBeUndefined();
    expect(execution.error?.message).toContain("trusted scope violation");
    await assertFileMissing(path.join(harness.workspaceDir, "trusted.txt"));
    await assertFileMissing(path.join(harness.workspaceDir, "hacked.txt"));

    const evidenceRecords = await readJsonlRecords(harness.evidencePath);
    const eventsByReqId = groupEvidenceByReqId(evidenceRecords);
    const violationReqId = [...eventsByReqId.entries()].find(([, events]) => {
      return events.includes("authorize") && events.includes("violation");
    })?.[0];
    expect(violationReqId).toBeTruthy();
  } finally {
    await cleanupTrustedIsolationTest({ harness, backend });
  }
});
