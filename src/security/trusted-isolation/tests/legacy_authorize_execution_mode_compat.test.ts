import crypto from "node:crypto";
import { expect, test } from "vitest";
import {
  createTrustedIsolationHarness,
  extractToolResultText,
  readJsonlRecords,
  reserveTrustedIsolationPort,
  runExecThroughTrustedIsolation,
  startMockTrustedServer,
  writeTrustedIsolationConfig,
} from "../../../../scripts/lib/trusted-isolation/harness.ts";
import { cleanupTrustedIsolationTest } from "./helpers.ts";

function toBase64Url(input: Buffer | string): string {
  const raw = Buffer.isBuffer(input) ? input : Buffer.from(input, "utf8");
  return raw.toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function createLegacyScopeToken(params: {
  request: Record<string, unknown>;
  hmacKey: string;
}): string {
  const payload = {
    version: 1,
    reqId: params.request.reqId,
    sid: params.request.sid,
    action: params.request.action,
    object: params.request.object,
    scope: params.request.scope,
    normalizedScopeDigest: params.request.normalizedScopeDigest,
    issuedAtMs: params.request.issuedAtMs,
    expiresAtMs: Number(params.request.issuedAtMs) + Number(params.request.ttlMs),
  };
  const payloadB64 = toBase64Url(JSON.stringify(payload));
  const signatureB64 = toBase64Url(
    crypto.createHmac("sha256", params.hmacKey).update(payloadB64).digest(),
  );
  return `${payloadB64}.${signatureB64}`;
}

test("legacy authorize responses without executionMode remain compatible", async () => {
  const hmacKey = "dev-trusted-hmac-secret";
  const harness = await createTrustedIsolationHarness({ name: "legacy-authorize-compat" });
  const backend = await startMockTrustedServer({
    port: await reserveTrustedIsolationPort(),
    authorize: (request) => {
      const normalizedRequest = {
        ...(request as Record<string, unknown>),
        requestDigest: "legacy-request-digest",
      };
      return {
        status: 200,
        body: {
          allow: true,
          decision: "dia",
          level: "L1",
          reason: "legacy low-risk exec command echo",
          matchedRuleId: "exec.action.low-risk",
          normalizedRequest,
          classification: {
            actionRisk: {
              level: "L1",
              reason: "legacy low-risk exec command echo",
              matchedRuleId: "exec.action.low-risk",
              commandClass: "low-risk",
            },
            objectRisk: {
              level: "L0",
              reason: "ordinary workspace object target",
              matchedRuleId: "object.ordinary.workspace",
              classification: "ordinary",
            },
            contextRisk: {
              level: "L0",
              reason: "ordinary execution context",
              matchedRuleId: "context.ordinary",
              factors: {},
            },
            effectRisk: {
              level: "L0",
              reason: "ordinary execution effect",
              matchedRuleId: "effect.ordinary",
              factors: {},
            },
            contextFlags: {
              protected_path: false,
              remote_target: false,
              shell_wrapper: false,
              export: false,
              destructive: false,
              multi_step: false,
              outside_workspace: false,
              task_mismatch: false,
              user_absent: false,
            },
            effectFlags: {
              protected_path: false,
              remote_target: false,
              shell_wrapper: false,
              export: false,
              destructive: false,
              multi_step: false,
              outside_workspace: false,
              task_mismatch: false,
              user_absent: false,
            },
            finalRiskLevel: "L1",
            decision: "dia",
            reason: "legacy low-risk exec command echo",
            matchedRuleId: "exec.action.low-risk",
          },
          scopeToken: createLegacyScopeToken({
            request: normalizedRequest,
            hmacKey,
          }),
          evidence: {
            backend: "legacy-trusted-backend",
            adaptor: "local-tdx",
            platform: "tdx",
            proofPath: "legacy",
          },
        },
      };
    },
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
      command: "echo legacy-compatible",
      runId: "run-legacy-authorize-compat",
      toolCallId: "tc-legacy-authorize-compat",
    });

    expect(execution.hook.blocked).toBe(false);
    expect(execution.error).toBeUndefined();
    expect(extractToolResultText(execution.result)).toContain("legacy-compatible");

    const evidenceRecords = await readJsonlRecords(harness.evidencePath);
    expect(
      evidenceRecords.some((entry) => {
        return (
          entry.event === "authorize" &&
          entry.executionMode === "ree-constrained" &&
          entry.decision === "dia"
        );
      }),
    ).toBe(true);
  } finally {
    await cleanupTrustedIsolationTest({ harness, backend });
  }
});
