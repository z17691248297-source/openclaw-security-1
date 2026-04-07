import fs from "node:fs/promises";
import path from "node:path";
import { afterEach, expect, test, vi } from "vitest";
import {
  createTrustedIsolationHarness,
  readJsonlRecords,
  reserveTrustedIsolationPort,
  runExecThroughTrustedIsolation,
  startStandaloneTrustedBackend,
  writeTrustedIsolationConfig,
} from "../../scripts/lib/trusted-isolation/harness.ts";

const callGatewayToolMock = vi.hoisted(() => vi.fn());

vi.mock("./tools/gateway.js", () => ({
  callGatewayTool: callGatewayToolMock,
}));

afterEach(() => {
  vi.clearAllMocks();
});

async function cleanupHarness(rootDir: string, stop?: () => Promise<void>) {
  await stop?.().catch(() => undefined);
  await fs.rm(rootDir, { recursive: true, force: true });
}

async function seedDocsFixture(workspaceDir: string) {
  const docsDir = path.join(workspaceDir, "docs");
  await fs.mkdir(docsDir, { recursive: true });
  await fs.writeFile(path.join(docsDir, "README.md"), "trusted confirmation fixture\n", "utf8");
}

test("trusted confirmation prompt prefers bare approval decisions", async () => {
  const hmacKey = "dev-trusted-hmac-secret";
  const harness = await createTrustedIsolationHarness({ name: "trusted-confirm-prompt" });
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

    callGatewayToolMock.mockImplementation(async (method, _opts, params) => {
      if (method === "exec.approval.request") {
        return {
          status: "accepted",
          id: String((params as { id?: string }).id ?? "trusted:prompt"),
        };
      }
      if (method === "exec.approval.waitDecision") {
        return {};
      }
      throw new Error(`unexpected gateway method: ${method}`);
    });

    const execution = await runExecThroughTrustedIsolation({
      harness,
      command: "tar -czf workspace.tgz docs",
      runId: "run-trusted-confirm-prompt",
      toolCallId: "tc-trusted-confirm-prompt",
    });

    expect(execution.hook.blocked).toBe(true);
    if (execution.hook.blocked) {
      expect(execution.hook.reason).toContain("reply with allow-once|allow-always|deny");
      expect(execution.hook.reason).toContain("/approve trusted:");
    }
  } finally {
    await cleanupHarness(harness.rootDir, backend.stop);
  }
});

test("expired trusted confirmations surface an explicit expiry reason", async () => {
  const hmacKey = "dev-trusted-hmac-secret";
  const harness = await createTrustedIsolationHarness({ name: "trusted-confirm-expired" });
  const backend = await startStandaloneTrustedBackend({
    harness,
    port: await reserveTrustedIsolationPort(),
    hmacKey,
    confirmationTimeoutMs: 150,
    confirmationExpiredRetentionMs: 60_000,
  });

  try {
    await writeTrustedIsolationConfig({
      harness,
      enabled: true,
      backendBaseUrl: backend.baseUrl,
      hmacKey,
      ttlMs: 200,
    });

    callGatewayToolMock.mockImplementation(async (method, _opts, params) => {
      if (method === "exec.approval.request") {
        return {
          status: "accepted",
          id: String((params as { id?: string }).id ?? "trusted:expired"),
        };
      }
      if (method === "exec.approval.waitDecision") {
        await new Promise((resolve) => setTimeout(resolve, 300));
        return {
          decision: "allow-once",
          resolvedBy: "Chat approval (whatsapp:+15555550123)",
        };
      }
      throw new Error(`unexpected gateway method: ${method}`);
    });

    const execution = await runExecThroughTrustedIsolation({
      harness,
      command: "tar -czf workspace.tgz docs",
      runId: "run-trusted-confirm-expired",
      toolCallId: "tc-trusted-confirm-expired",
    });

    expect(execution.hook.blocked).toBe(true);
    if (execution.hook.blocked) {
      expect(execution.hook.reason).toContain("trusted confirmation expired");
      expect(execution.hook.reason).not.toContain("invalid response");
    }
  } finally {
    await cleanupHarness(harness.rootDir, backend.stop);
  }
});

test("trusted confirmation survives human delay beyond the request ttl and executes", async () => {
  const hmacKey = "dev-trusted-hmac-secret";
  const harness = await createTrustedIsolationHarness({ name: "trusted-confirm-success" });
  const backend = await startStandaloneTrustedBackend({
    harness,
    port: await reserveTrustedIsolationPort(),
    hmacKey,
    confirmationTimeoutMs: 1_000,
    confirmationExpiredRetentionMs: 60_000,
  });

  try {
    await seedDocsFixture(harness.workspaceDir);
    await writeTrustedIsolationConfig({
      harness,
      enabled: true,
      backendBaseUrl: backend.baseUrl,
      hmacKey,
      ttlMs: 200,
    });

    callGatewayToolMock.mockImplementation(async (method, _opts, params) => {
      if (method === "exec.approval.request") {
        return {
          status: "accepted",
          id: String((params as { id?: string }).id ?? "trusted:success"),
        };
      }
      if (method === "exec.approval.waitDecision") {
        await new Promise((resolve) => setTimeout(resolve, 300));
        return {
          decision: "allow-once",
          resolvedBy: "Chat approval (whatsapp:+15555550123)",
        };
      }
      throw new Error(`unexpected gateway method: ${method}`);
    });

    const execution = await runExecThroughTrustedIsolation({
      harness,
      command: "tar -czf workspace.tgz docs",
      runId: "run-trusted-confirm-success",
      toolCallId: "tc-trusted-confirm-success",
    });

    expect(execution.hook.blocked).toBe(false);
    expect(execution.error).toBeUndefined();
    await expect(
      fs.access(path.join(harness.workspaceDir, "workspace.tgz")),
    ).resolves.toBeUndefined();

    const evidenceRecords = await readJsonlRecords(harness.evidencePath);
    const confirmRecord = evidenceRecords.find((entry) => {
      return entry.event === "confirm" && entry.status === "approved";
    });
    expect(confirmRecord).toBeTruthy();
    const reqId = typeof confirmRecord?.reqId === "string" ? confirmRecord.reqId : "";
    expect(reqId).toBeTruthy();
    const events = evidenceRecords
      .filter((entry) => entry.reqId === reqId)
      .map((entry) => String(entry.event));
    expect(events).toEqual(expect.arrayContaining(["authorize", "confirm", "complete"]));
  } finally {
    await cleanupHarness(harness.rootDir, backend.stop);
  }
});
