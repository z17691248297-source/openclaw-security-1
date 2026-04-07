#!/usr/bin/env node

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { scaffoldTrustedBackendStandalone } from "./scaffold-trusted-backend-standalone.mjs";

const smokeRoot =
  process.env.OPENCLAW_TRUSTED_SMOKE_ROOT?.trim() ||
  path.join(os.tmpdir(), "openclaw-trusted-isolation");
const backendPort = Number.parseInt(process.env.OPENCLAW_TRUSTED_BACKEND_PORT ?? "19090", 10);
const backendBaseUrl = `http://127.0.0.1:${backendPort}`;
const trustedHmacKey = process.env.OPENCLAW_TRUSTED_HMAC_KEY?.trim() || "dev-trusted-hmac-secret";
const backendDir =
  process.env.OPENCLAW_TRUSTED_BACKEND_DIR?.trim() || path.join(smokeRoot, "trusted-backend");
const configPath = path.join(smokeRoot, "openclaw.json");
const stateDir = path.join(smokeRoot, "state");
const workspaceDir = path.join(smokeRoot, "workspace");
const evidencePath = path.join(stateDir, "security", "trusted-evidence.jsonl");
const backendEventsPath = path.join(smokeRoot, "trusted-backend-events.jsonl");

function toolResultText(result: unknown): string {
  if (!result || typeof result !== "object") {
    return "";
  }
  const content = (result as { content?: Array<{ type?: string; text?: string }> }).content ?? [];
  return content
    .filter((block) => block?.type === "text" && typeof block.text === "string")
    .map((block) => block.text)
    .join("\n");
}

async function writeConfigFile() {
  await fs.mkdir(workspaceDir, { recursive: true });
  await fs.mkdir(stateDir, { recursive: true });
  const config = {
    gateway: {
      mode: "local",
      bind: "loopback",
      port: 18789,
    },
    tools: {
      trustedIsolation: {
        enabled: true,
        enforceFailClosed: true,
        backendBaseUrl,
        authorizePath: "/v1/trusted/authorize",
        completePath: "/v1/trusted/complete",
        requestTimeoutMs: 5_000,
        ttlMs: 15_000,
        verify: {
          mode: "hmac-sha256",
          hmacKey: trustedHmacKey,
          requireScopeToken: true,
        },
        forceTrustedActions: ["exec"],
        evidenceFile: evidencePath,
      },
    },
  };
  await fs.writeFile(configPath, `${JSON.stringify(config, null, 2)}\n`, "utf8");
}

async function waitForBackend() {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    try {
      const response = await fetch(`${backendBaseUrl}/healthz`);
      if (response.ok) {
        return;
      }
    } catch {
      // Retry until the backend is up.
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`trusted backend did not become healthy at ${backendBaseUrl}`);
}

async function readJsonl(filePath: string): Promise<Array<Record<string, unknown>>> {
  const raw = await fs.readFile(filePath, "utf8");
  return raw
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

async function main() {
  await fs.rm(smokeRoot, { recursive: true, force: true });
  await scaffoldTrustedBackendStandalone({
    targetDir: backendDir,
    force: true,
  });
  await writeConfigFile();

  process.env.OPENCLAW_CONFIG_PATH = configPath;
  process.env.OPENCLAW_STATE_DIR = stateDir;
  process.env.OPENCLAW_HOME = smokeRoot;

  const backend = spawn(process.execPath, ["server.mjs"], {
    cwd: backendDir,
    env: {
      ...process.env,
      TRUSTED_BACKEND_PORT: String(backendPort),
      TRUSTED_HMAC_KEY: trustedHmacKey,
      TRUSTED_BACKEND_EVENTS_FILE: backendEventsPath,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  const backendLogs: string[] = [];
  backend.stdout.on("data", (chunk) => {
    backendLogs.push(String(chunk));
  });
  backend.stderr.on("data", (chunk) => {
    backendLogs.push(String(chunk));
  });

  try {
    await waitForBackend();

    const { clearConfigCache } = await import("../src/config/config.ts");
    const { runBeforeToolCallHook } = await import("../src/agents/pi-tools.before-tool-call.ts");
    const { createExecTool } = await import("../src/agents/bash-tools.exec.ts");
    const { finalizeTrustedIsolationToolCall } =
      await import("../src/security/trusted-isolation/runtime.ts");

    clearConfigCache();

    const execTool = createExecTool({
      agentId: "ti-agent",
      cwd: workspaceDir,
      host: "gateway",
      security: "full",
      ask: "off",
      allowBackground: false,
    });

    const authorized = await runBeforeToolCallHook({
      toolName: "exec",
      params: {
        command: "echo trusted-hi",
        workdir: workspaceDir,
      },
      toolCallId: "tc-allow",
      ctx: {
        agentId: "ti-agent",
        sessionId: "trusted-session",
        runId: "run-allow",
      },
    });
    assert.equal(authorized.blocked, false, "trusted authorize should allow high-risk exec");

    const allowResult = await execTool.execute("tc-allow", authorized.params, undefined);
    assert.match(toolResultText(allowResult), /trusted-hi/, "authorized exec should run");
    await finalizeTrustedIsolationToolCall({
      toolName: "exec",
      toolCallId: "tc-allow",
      runId: "run-allow",
      isError: false,
      result: allowResult,
    });

    const mismatch = await runBeforeToolCallHook({
      toolName: "exec",
      params: {
        command: "echo locked-command",
        workdir: workspaceDir,
      },
      toolCallId: "tc-mismatch",
      ctx: {
        agentId: "ti-agent",
        sessionId: "trusted-session",
        runId: "run-mismatch",
      },
    });
    assert.equal(mismatch.blocked, false, "trusted authorize should return a scope token");

    let mismatchError = "";
    try {
      await execTool.execute(
        "tc-mismatch",
        {
          ...(mismatch.params as Record<string, unknown>),
          command: "echo tampered-command",
        },
        undefined,
      );
    } catch (error) {
      mismatchError = error instanceof Error ? error.message : String(error);
    }
    assert.match(
      mismatchError,
      /trusted scope violation: command differs from approved command/,
      "executor should reject scope mismatch",
    );

    const backendEvents = await readJsonl(backendEventsPath);
    const evidenceEvents = await readJsonl(evidencePath);
    const authorizeBodies = backendEvents.filter((entry) => entry.event === "authorize");
    assert.ok(authorizeBodies.length >= 2, "backend should receive authorize requests");

    const evidenceByReqId = new Map<string, Set<string>>();
    for (const entry of evidenceEvents) {
      const reqId = typeof entry.reqId === "string" ? entry.reqId : "";
      const event = typeof entry.event === "string" ? entry.event : "";
      if (!reqId || !event) {
        continue;
      }
      const events = evidenceByReqId.get(reqId) ?? new Set<string>();
      events.add(event);
      evidenceByReqId.set(reqId, events);
    }
    const pairedReqId = [...evidenceByReqId.entries()].find(
      ([, events]) => events.has("authorize") && events.has("complete"),
    )?.[0];
    assert.ok(pairedReqId, "trusted-evidence.jsonl should contain an authorize/complete pair");

    const summary = {
      smokeRoot,
      backendDir,
      configPath,
      stateDir,
      workspaceDir,
      backendBaseUrl,
      evidencePath,
      backendEventsPath,
      checks: {
        highRiskExecAuthorized: true,
        scopeMismatchRejected: true,
        authorizeCompletePaired: true,
      },
      pairedReqId,
      backendLogTail: backendLogs.join("").trim().split("\n").slice(-5),
    };

    console.log(JSON.stringify(summary, null, 2));
  } finally {
    backend.kill("SIGTERM");
    await new Promise((resolve) => backend.once("exit", () => resolve(undefined)));
  }
}

void main().catch((error) => {
  console.error(error instanceof Error ? error.stack || error.message : String(error));
  process.exit(1);
});
