#!/usr/bin/env node

import path from "node:path";
import {
  assertFileMissing,
  authorizeExecToolCall,
  createTrustedIsolationHarness,
  executeAuthorizedExec,
  readJsonlRecords,
  readPemFile,
  readTrustedEvidenceSummary,
  reserveTrustedIsolationPort,
  runExecThroughTrustedIsolation,
  startStandaloneTrustedBackend,
  writeTrustedIsolationConfig,
} from "./lib/trusted-isolation/harness.ts";

function parseArgs(argv: string[]): {
  backendBaseUrl?: string;
  adaptor?: "local-tdx" | "trustzone-remote-backend" | "keystone-remote-backend";
  verifyMode: "hmac-sha256" | "ed25519";
  hmacKey?: string;
  publicKeyFile?: string;
  privateKeyFile?: string;
} {
  const result = {
    verifyMode: (process.env.OPENCLAW_TRUSTED_VERIFY_MODE?.trim() || "hmac-sha256") as
      | "hmac-sha256"
      | "ed25519",
    hmacKey: process.env.OPENCLAW_TRUSTED_HMAC_KEY?.trim() || "dev-trusted-hmac-secret",
    publicKeyFile: process.env.OPENCLAW_TRUSTED_PUBLIC_KEY_FILE?.trim(),
    privateKeyFile: process.env.OPENCLAW_TRUSTED_PRIVATE_KEY_FILE?.trim(),
  } as {
    backendBaseUrl?: string;
    adaptor?: "local-tdx" | "trustzone-remote-backend" | "keystone-remote-backend";
    verifyMode: "hmac-sha256" | "ed25519";
    hmacKey?: string;
    publicKeyFile?: string;
    privateKeyFile?: string;
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--backend-base-url") {
      result.backendBaseUrl = argv[index + 1];
      index += 1;
      continue;
    }
    if (arg === "--adaptor") {
      result.adaptor = argv[index + 1] as typeof result.adaptor;
      index += 1;
      continue;
    }
    if (arg === "--verify-mode") {
      result.verifyMode = (argv[index + 1] ?? result.verifyMode) as typeof result.verifyMode;
      index += 1;
      continue;
    }
    if (arg === "--hmac-key") {
      result.hmacKey = argv[index + 1] ?? result.hmacKey;
      index += 1;
      continue;
    }
    if (arg === "--public-key-file") {
      result.publicKeyFile = argv[index + 1] ?? result.publicKeyFile;
      index += 1;
      continue;
    }
    if (arg === "--private-key-file") {
      result.privateKeyFile = argv[index + 1] ?? result.privateKeyFile;
      index += 1;
    }
  }
  return result;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.verifyMode === "ed25519" && !args.publicKeyFile) {
    throw new Error("ed25519 mode requires --public-key-file");
  }
  if (!args.backendBaseUrl && args.verifyMode === "ed25519" && !args.privateKeyFile) {
    throw new Error("local ed25519 smoke requires --private-key-file");
  }
  const publicKeyPem = args.publicKeyFile ? await readPemFile(args.publicKeyFile) : undefined;
  const harness = await createTrustedIsolationHarness({ name: "paper-smoke" });
  const localPort = await reserveTrustedIsolationPort();
  const localBackend = args.backendBaseUrl
    ? undefined
    : await startStandaloneTrustedBackend({
        harness,
        port: localPort,
        verifyMode: args.verifyMode,
        hmacKey: args.hmacKey,
        privateKeyFile: args.privateKeyFile,
        adaptor: args.adaptor ?? "local-tdx",
      });
  const backendBaseUrl = args.backendBaseUrl ?? localBackend?.baseUrl;
  if (!backendBaseUrl) {
    throw new Error("backendBaseUrl resolution failed");
  }

  try {
    await writeTrustedIsolationConfig({
      harness,
      enabled: true,
      backendBaseUrl,
      verifyMode: args.verifyMode,
      hmacKey: args.verifyMode === "hmac-sha256" ? args.hmacKey : undefined,
      publicKeyPem,
    });

    const allowCase = await runExecThroughTrustedIsolation({
      harness,
      command: "echo trusted-hi",
      runId: "paper-allow",
      toolCallId: "tc-paper-allow",
    });

    const scopeHook = await authorizeExecToolCall({
      harness,
      command: "printf trusted-hi > trusted.txt",
      runId: "paper-violation",
      toolCallId: "tc-paper-violation",
    });
    const scopeViolation =
      scopeHook.blocked === false
        ? await executeAuthorizedExec({
            harness,
            authorizedParams: scopeHook.params,
            runId: "paper-violation",
            toolCallId: "tc-paper-violation",
            tamperedCommand: "printf hacked > hacked.txt",
          })
        : { error: new Error(scopeHook.reason) };
    await assertFileMissing(path.join(harness.workspaceDir, "trusted.txt"));
    await assertFileMissing(path.join(harness.workspaceDir, "hacked.txt"));

    await writeTrustedIsolationConfig({
      harness,
      enabled: true,
      backendBaseUrl,
      verifyMode: args.verifyMode,
      hmacKey: args.verifyMode === "hmac-sha256" ? args.hmacKey : undefined,
      publicKeyPem,
      ttlMs: 100,
    });
    const ttlHook = await authorizeExecToolCall({
      harness,
      command: "echo ttl-expired",
      runId: "paper-ttl",
      toolCallId: "tc-paper-ttl",
    });
    await new Promise((resolve) => setTimeout(resolve, 150));
    const ttlCase =
      ttlHook.blocked === false
        ? await executeAuthorizedExec({
            harness,
            authorizedParams: ttlHook.params,
            runId: "paper-ttl",
            toolCallId: "tc-paper-ttl",
          })
        : { error: new Error(ttlHook.reason) };

    await writeTrustedIsolationConfig({
      harness,
      enabled: true,
      backendBaseUrl: "http://127.0.0.1:19599",
      verifyMode: args.verifyMode,
      hmacKey: args.verifyMode === "hmac-sha256" ? args.hmacKey : undefined,
      publicKeyPem,
      requestTimeoutMs: 500,
    });
    const failClosedCase = await runExecThroughTrustedIsolation({
      harness,
      command: "echo blocked > blocked.txt",
      runId: "paper-fail-closed",
      toolCallId: "tc-paper-fail-closed",
    });
    await assertFileMissing(path.join(harness.workspaceDir, "blocked.txt"));

    const evidenceSummary = await readTrustedEvidenceSummary(harness.evidencePath);
    const evidenceRecords = await readJsonlRecords(harness.evidencePath);
    const authorizeCompletePair = evidenceRecords.some((entry, index, records) => {
      const reqId = entry.reqId;
      return (
        entry.event === "authorize" &&
        records.some((candidate) => candidate.reqId === reqId && candidate.event === "complete")
      );
    });
    const authorizeViolationPair = evidenceRecords.some((entry, index, records) => {
      const reqId = entry.reqId;
      return (
        entry.event === "authorize" &&
        records.some((candidate) => candidate.reqId === reqId && candidate.event === "violation")
      );
    });

    const summary = {
      backendBaseUrl,
      backendMode: args.backendBaseUrl ? "remote" : "local-standalone",
      checks: {
        allow: allowCase.hook.blocked === false && !allowCase.error,
        scopeViolation:
          scopeHook.blocked === false &&
          Boolean(scopeViolation.error?.message.includes("trusted scope violation")),
        ttlExpired: Boolean(
          ttlCase.error?.message.match(/trusted scope token expired|trusted scope violation/),
        ),
        failClosed:
          failClosedCase.hook.blocked === true &&
          failClosedCase.hook.reason.includes("trusted backend unavailable"),
        evidenceConsistency: evidenceSummary.ok,
        authorizeCompletePair,
        authorizeViolationPair,
      },
      evidencePath: harness.evidencePath,
      evidenceSummary,
    };

    console.log(JSON.stringify(summary, null, 2));
    if (Object.values(summary.checks).some((value) => value !== true)) {
      process.exitCode = 1;
    }
  } finally {
    await localBackend?.stop();
  }
}

void main().catch((error) => {
  console.error(error instanceof Error ? error.stack || error.message : String(error));
  process.exit(1);
});
