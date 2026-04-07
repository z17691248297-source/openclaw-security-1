#!/usr/bin/env node

import fs from "node:fs/promises";
import {
  createTrustedIsolationHarness,
  extractToolResultText,
  readPemFile,
  reserveTrustedIsolationPort,
  runExecThroughTrustedIsolation,
  runMeasuredExecThroughTrustedIsolation,
  startStandaloneTrustedBackend,
  writeTrustedIsolationConfig,
} from "./lib/trusted-isolation/harness.ts";

type CsvRow = {
  mode: string;
  case: string;
  run_id: number;
  authorize_ms: number;
  complete_ms: number;
  e2e_ms: number;
  result: string;
};

function parseArgs(argv: string[]): {
  runs: number;
  output: string;
  guestBackendBaseUrl?: string;
  verifyMode: "hmac-sha256" | "ed25519";
  hmacKey?: string;
  publicKeyFile?: string;
  privateKeyFile?: string;
} {
  const result = {
    runs: 30,
    output: "trusted-isolation-bench.csv",
    guestBackendBaseUrl: process.env.OPENCLAW_TRUSTED_GUEST_BACKEND_BASE_URL?.trim(),
    verifyMode: (process.env.OPENCLAW_TRUSTED_VERIFY_MODE?.trim() || "hmac-sha256") as
      | "hmac-sha256"
      | "ed25519",
    hmacKey: process.env.OPENCLAW_TRUSTED_HMAC_KEY?.trim() || "dev-trusted-hmac-secret",
    publicKeyFile: process.env.OPENCLAW_TRUSTED_PUBLIC_KEY_FILE?.trim(),
    privateKeyFile: process.env.OPENCLAW_TRUSTED_PRIVATE_KEY_FILE?.trim(),
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--runs") {
      result.runs = Number.parseInt(argv[index + 1] ?? `${result.runs}`, 10);
      index += 1;
      continue;
    }
    if (arg === "--output") {
      result.output = argv[index + 1] ?? result.output;
      index += 1;
      continue;
    }
    if (arg === "--guest-backend-base-url") {
      result.guestBackendBaseUrl = argv[index + 1] ?? result.guestBackendBaseUrl;
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

async function runMode(params: {
  mode: "baseline" | "protected-local" | "protected-guest";
  runs: number;
  backendBaseUrl?: string;
  verifyMode: "hmac-sha256" | "ed25519";
  hmacKey?: string;
  publicKeyPem?: string;
}): Promise<CsvRow[]> {
  const harness = await createTrustedIsolationHarness({ name: params.mode });
  try {
    await writeTrustedIsolationConfig({
      harness,
      enabled: params.mode !== "baseline",
      ...(params.backendBaseUrl ? { backendBaseUrl: params.backendBaseUrl } : {}),
      verifyMode: params.verifyMode,
      hmacKey: params.verifyMode === "hmac-sha256" ? params.hmacKey : undefined,
      publicKeyPem: params.publicKeyPem,
    });

    const rows: CsvRow[] = [];
    for (let runId = 1; runId <= params.runs; runId += 1) {
      if (params.mode === "baseline") {
        const start = performance.now();
        const execution = await runExecThroughTrustedIsolation({
          harness,
          command: "echo baseline-bench",
          runId: `${params.mode}-${runId}`,
          toolCallId: `tc-${params.mode}-${runId}`,
        });
        rows.push({
          mode: params.mode,
          case: "echo baseline-bench",
          run_id: runId,
          authorize_ms: 0,
          complete_ms: 0,
          e2e_ms: performance.now() - start,
          result: execution.error
            ? `error:${execution.error.message}`
            : execution.hook.blocked
              ? `blocked:${execution.hook.reason}`
              : `ok:${extractToolResultText(execution.result).trim()}`,
        });
        continue;
      }

      const execution = await runMeasuredExecThroughTrustedIsolation({
        harness,
        command: "echo protected-bench",
        runId: `${params.mode}-${runId}`,
        toolCallId: `tc-${params.mode}-${runId}`,
      });
      rows.push({
        mode: params.mode,
        case: "echo protected-bench",
        run_id: runId,
        authorize_ms: execution.authorizeMs,
        complete_ms: execution.completeMs,
        e2e_ms: execution.e2eMs,
        result: execution.error
          ? `error:${execution.error.message}`
          : execution.hook.blocked
            ? `blocked:${execution.hook.reason}`
            : `ok:${extractToolResultText(execution.result).trim()}`,
      });
    }
    return rows;
  } finally {
    await fs.rm(harness.rootDir, { recursive: true, force: true });
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.verifyMode === "ed25519" && !args.publicKeyFile) {
    throw new Error("ed25519 mode requires --public-key-file");
  }
  if (args.verifyMode === "ed25519" && !args.privateKeyFile) {
    throw new Error("local ed25519 bench requires --private-key-file");
  }
  const publicKeyPem = args.publicKeyFile ? await readPemFile(args.publicKeyFile) : undefined;
  const localHarness = await createTrustedIsolationHarness({ name: "bench-local-backend" });
  const localBackend = await startStandaloneTrustedBackend({
    harness: localHarness,
    port: await reserveTrustedIsolationPort(),
    verifyMode: args.verifyMode,
    hmacKey: args.hmacKey,
    privateKeyFile: args.privateKeyFile,
  });

  try {
    const rows: CsvRow[] = [];
    rows.push(
      ...(await runMode({
        mode: "baseline",
        runs: args.runs,
        verifyMode: args.verifyMode,
        hmacKey: args.hmacKey,
        publicKeyPem,
      })),
    );
    rows.push(
      ...(await runMode({
        mode: "protected-local",
        runs: args.runs,
        backendBaseUrl: localBackend.baseUrl,
        verifyMode: args.verifyMode,
        hmacKey: args.hmacKey,
        publicKeyPem,
      })),
    );
    if (args.guestBackendBaseUrl) {
      rows.push(
        ...(await runMode({
          mode: "protected-guest",
          runs: args.runs,
          backendBaseUrl: args.guestBackendBaseUrl,
          verifyMode: args.verifyMode,
          hmacKey: args.hmacKey,
          publicKeyPem,
        })),
      );
    }

    const csv = [
      "mode,case,run_id,authorize_ms,complete_ms,e2e_ms,result",
      ...rows.map((row) =>
        [
          row.mode,
          JSON.stringify(row.case),
          row.run_id,
          row.authorize_ms.toFixed(3),
          row.complete_ms.toFixed(3),
          row.e2e_ms.toFixed(3),
          JSON.stringify(row.result),
        ].join(","),
      ),
    ].join("\n");
    await fs.writeFile(args.output, `${csv}\n`, "utf8");
    console.log(JSON.stringify({ output: args.output, rows: rows.length }, null, 2));
  } finally {
    await localBackend.stop();
    await fs.rm(localHarness.rootDir, { recursive: true, force: true });
  }
}

void main().catch((error) => {
  console.error(error instanceof Error ? error.stack || error.message : String(error));
  process.exit(1);
});
