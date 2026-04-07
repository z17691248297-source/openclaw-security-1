import { expect, test } from "vitest";
import {
  createTrustedIsolationHarness,
  readJsonlRecords,
  reserveTrustedIsolationPort,
  runExecThroughTrustedIsolation,
  startMockTrustedServer,
  writeTrustedIsolationConfig,
} from "../../../../scripts/lib/trusted-isolation/harness.ts";
import { cleanupTrustedIsolationTest } from "./helpers.ts";

test("malformed authorize response fail-closes forced exec", async () => {
  const harness = await createTrustedIsolationHarness({ name: "malformed-authorize" });
  const backend = await startMockTrustedServer({
    port: await reserveTrustedIsolationPort(),
    authorize: () => ({
      status: 200,
      body: '{"allow": true',
    }),
  });

  try {
    await writeTrustedIsolationConfig({
      harness,
      enabled: true,
      backendBaseUrl: backend.baseUrl,
      hmacKey: "dev-trusted-hmac-secret",
    });

    const execution = await runExecThroughTrustedIsolation({
      harness,
      command: "echo malformed-backend",
      runId: "run-malformed-authorize",
      toolCallId: "tc-malformed-authorize",
    });

    expect(execution.hook.blocked).toBe(true);
    if (execution.hook.blocked) {
      expect(execution.hook.reason).toContain("trusted authorization invalid response");
    }

    const evidenceRecords = await readJsonlRecords(harness.evidencePath);
    expect(
      evidenceRecords.some((entry) => {
        return (
          entry.event === "backend_error" &&
          entry.errorCode === "trusted_authorization_invalid_response"
        );
      }),
    ).toBe(true);
  } finally {
    await cleanupTrustedIsolationTest({ harness, backend });
  }
});
