import { expect, test } from "vitest";
import {
  authorizeExecToolCall,
  createTrustedIsolationHarness,
  executeAuthorizedExec,
  reserveTrustedIsolationPort,
  startStandaloneTrustedBackend,
  writeTrustedIsolationConfig,
} from "../../../../scripts/lib/trusted-isolation/harness.ts";
import { cleanupTrustedIsolationTest } from "./helpers.ts";

test("expired tokens are rejected before exec", async () => {
  const hmacKey = "dev-trusted-hmac-secret";
  const harness = await createTrustedIsolationHarness({ name: "ttl-expired" });
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
      ttlMs: 100,
    });

    const hook = await authorizeExecToolCall({
      harness,
      command: "echo ttl-expired",
      runId: "run-ttl-expired",
      toolCallId: "tc-ttl-expired",
    });

    expect(hook.blocked).toBe(false);
    if (hook.blocked) {
      return;
    }

    await new Promise((resolve) => setTimeout(resolve, 150));
    const execution = await executeAuthorizedExec({
      harness,
      authorizedParams: hook.params,
      runId: "run-ttl-expired",
      toolCallId: "tc-ttl-expired",
    });

    expect(execution.result).toBeUndefined();
    expect(execution.error?.message).toMatch(/trusted scope token expired|trusted scope violation/);
  } finally {
    await cleanupTrustedIsolationTest({ harness, backend });
  }
});
