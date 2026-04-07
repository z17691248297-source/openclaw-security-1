import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs/promises";
import { createServer } from "node:net";
import os from "node:os";
import path from "node:path";
import type { AgentToolResult } from "@mariozechner/pi-agent-core";
import { scaffoldTrustedBackendStandalone } from "../../scaffold-trusted-backend-standalone.mjs";

export type TrustedIsolationHarness = {
  rootDir: string;
  stateDir: string;
  workspaceDir: string;
  configPath: string;
  evidencePath: string;
  backendDir: string;
  backendEventsPath: string;
  backendBaseUrl: string;
  agentId: string;
  sessionKey: string;
};

export type TrustedBackendHandle = {
  baseUrl: string;
  stop: () => Promise<void>;
  stdout: string[];
  stderr: string[];
};

export async function readPemFile(filePath: string): Promise<string> {
  return await fs.readFile(path.resolve(filePath), "utf8");
}

export function extractToolResultText(result: unknown): string {
  if (!result || typeof result !== "object") {
    return "";
  }
  const content = (result as { content?: Array<{ type?: string; text?: string }> }).content ?? [];
  return content
    .filter((block) => block?.type === "text" && typeof block.text === "string")
    .map((block) => block.text)
    .join("\n");
}

export async function createTrustedIsolationHarness(params?: {
  name?: string;
  agentId?: string;
  sessionKey?: string;
}): Promise<TrustedIsolationHarness> {
  const rootDir = await fs.mkdtemp(
    path.join(os.tmpdir(), `openclaw-trusted-isolation-${params?.name?.trim() || "paper"}-`),
  );
  const stateDir = path.join(rootDir, "state");
  const workspaceDir = path.join(rootDir, "workspace");
  const configPath = path.join(rootDir, "openclaw.json");
  const evidencePath = path.join(stateDir, "security", "trusted-evidence.jsonl");
  const backendDir = path.join(rootDir, "trusted-backend");
  const backendEventsPath = path.join(rootDir, "trusted-backend-events.jsonl");
  await fs.mkdir(stateDir, { recursive: true });
  await fs.mkdir(workspaceDir, { recursive: true });
  return {
    rootDir,
    stateDir,
    workspaceDir,
    configPath,
    evidencePath,
    backendDir,
    backendEventsPath,
    backendBaseUrl: "",
    agentId: params?.agentId?.trim() || "ti-agent",
    sessionKey: params?.sessionKey?.trim() || `trusted-session-${Date.now()}`,
  };
}

export async function writeTrustedIsolationConfig(params: {
  harness: TrustedIsolationHarness;
  enabled: boolean;
  backendBaseUrl?: string;
  ttlMs?: number;
  verifyMode?: "none" | "hmac-sha256" | "ed25519";
  hmacKey?: string;
  publicKeyPem?: string;
  requireScopeToken?: boolean;
  forceTrustedActions?: string[];
  forceTrustedTools?: string[];
  requestTimeoutMs?: number;
  evidenceFile?: string;
}): Promise<void> {
  const config = {
    gateway: {
      mode: "local",
      bind: "loopback",
      port: 18789,
    },
    tools: {
      trustedIsolation: {
        enabled: params.enabled,
        enforceFailClosed: true,
        ...(params.backendBaseUrl ? { backendBaseUrl: params.backendBaseUrl } : {}),
        authorizePath: "/v1/trusted/authorize",
        completePath: "/v1/trusted/complete",
        requestTimeoutMs: params.requestTimeoutMs ?? 5_000,
        ttlMs: params.ttlMs ?? 5_000,
        verify: {
          mode: params.verifyMode ?? "hmac-sha256",
          ...(params.hmacKey ? { hmacKey: params.hmacKey } : {}),
          ...(params.publicKeyPem ? { publicKeyPem: params.publicKeyPem } : {}),
          requireScopeToken: params.requireScopeToken ?? true,
        },
        forceTrustedActions: params.forceTrustedActions ?? ["exec"],
        forceTrustedTools: params.forceTrustedTools ?? [],
        ...(params.evidenceFile ? { evidenceFile: params.evidenceFile } : {}),
      },
    },
  };
  await fs.writeFile(params.harness.configPath, `${JSON.stringify(config, null, 2)}\n`, "utf8");
}

export async function withTrustedIsolationEnv<T>(
  harness: TrustedIsolationHarness,
  fn: () => Promise<T>,
): Promise<T> {
  const previous = {
    OPENCLAW_CONFIG_PATH: process.env.OPENCLAW_CONFIG_PATH,
    OPENCLAW_HOME: process.env.OPENCLAW_HOME,
    OPENCLAW_STATE_DIR: process.env.OPENCLAW_STATE_DIR,
  };
  process.env.OPENCLAW_CONFIG_PATH = harness.configPath;
  process.env.OPENCLAW_HOME = harness.rootDir;
  process.env.OPENCLAW_STATE_DIR = harness.stateDir;
  const { clearConfigCache, clearRuntimeConfigSnapshot } =
    await import("../../../src/config/config.ts");
  clearConfigCache();
  clearRuntimeConfigSnapshot();
  try {
    return await fn();
  } finally {
    if (previous.OPENCLAW_CONFIG_PATH === undefined) {
      delete process.env.OPENCLAW_CONFIG_PATH;
    } else {
      process.env.OPENCLAW_CONFIG_PATH = previous.OPENCLAW_CONFIG_PATH;
    }
    if (previous.OPENCLAW_HOME === undefined) {
      delete process.env.OPENCLAW_HOME;
    } else {
      process.env.OPENCLAW_HOME = previous.OPENCLAW_HOME;
    }
    if (previous.OPENCLAW_STATE_DIR === undefined) {
      delete process.env.OPENCLAW_STATE_DIR;
    } else {
      process.env.OPENCLAW_STATE_DIR = previous.OPENCLAW_STATE_DIR;
    }
    clearConfigCache();
    clearRuntimeConfigSnapshot();
  }
}

export async function reserveTrustedIsolationPort(): Promise<number> {
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve(undefined));
  });
  const address = server.address();
  const port =
    address && typeof address === "object" && typeof address.port === "number"
      ? address.port
      : undefined;
  await new Promise((resolve) => server.close(() => resolve(undefined)));
  if (!port) {
    throw new Error("failed to reserve trusted-isolation port");
  }
  return port;
}

async function waitForHttpOk(url: string): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      const response = await fetch(url);
      if (response.ok) {
        return;
      }
    } catch {
      // Retry until healthy.
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`timeout waiting for ${url}`);
}

function pipeChildOutput(child: ChildProcess, target: string[]): void {
  child.stdout?.on("data", (chunk) => target.push(String(chunk)));
  child.stderr?.on("data", (chunk) => target.push(String(chunk)));
}

export async function startStandaloneTrustedBackend(params: {
  harness: TrustedIsolationHarness;
  port: number;
  verifyMode?: "hmac-sha256" | "ed25519";
  hmacKey?: string;
  privateKeyFile?: string;
  privateKeyPem?: string;
  adaptor?: "local-tdx" | "trustzone-remote-backend" | "keystone-remote-backend";
  policyPath?: string;
  confirmationTimeoutMs?: number;
  confirmationExpiredRetentionMs?: number;
}): Promise<TrustedBackendHandle> {
  await scaffoldTrustedBackendStandalone({
    targetDir: params.harness.backendDir,
    force: true,
  });
  const stdout: string[] = [];
  const stderr: string[] = [];
  const child = spawn(process.execPath, ["server.mjs"], {
    cwd: params.harness.backendDir,
    env: {
      ...process.env,
      TRUSTED_BACKEND_HOST: "127.0.0.1",
      TRUSTED_BACKEND_PORT: String(params.port),
      TRUSTED_VERIFY_MODE: params.verifyMode ?? "hmac-sha256",
      ...(params.hmacKey ? { TRUSTED_HMAC_KEY: params.hmacKey } : {}),
      ...(params.privateKeyFile
        ? { TRUSTED_SIGNING_PRIVATE_KEY_FILE: path.resolve(params.privateKeyFile) }
        : {}),
      ...(params.privateKeyPem ? { TRUSTED_SIGNING_PRIVATE_KEY_PEM: params.privateKeyPem } : {}),
      TRUSTED_BACKEND_EVENTS_FILE: params.harness.backendEventsPath,
      TRUSTED_BACKEND_ADAPTOR: params.adaptor ?? "local-tdx",
      ...(params.policyPath ? { TRUSTED_POLICY_PATH: params.policyPath } : {}),
      ...(typeof params.confirmationTimeoutMs === "number" &&
      Number.isFinite(params.confirmationTimeoutMs) &&
      params.confirmationTimeoutMs > 0
        ? {
            TRUSTED_CONFIRMATION_TIMEOUT_MS: String(Math.floor(params.confirmationTimeoutMs)),
          }
        : {}),
      ...(typeof params.confirmationExpiredRetentionMs === "number" &&
      Number.isFinite(params.confirmationExpiredRetentionMs) &&
      params.confirmationExpiredRetentionMs > 0
        ? {
            TRUSTED_CONFIRMATION_EXPIRED_RETENTION_MS: String(
              Math.floor(params.confirmationExpiredRetentionMs),
            ),
          }
        : {}),
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  pipeChildOutput(child, stdout);
  pipeChildOutput(child, stderr);
  const baseUrl = `http://127.0.0.1:${params.port}`;
  await waitForHttpOk(`${baseUrl}/healthz`);
  return {
    baseUrl,
    stdout,
    stderr,
    stop: async () => {
      if (child.exitCode !== null || child.signalCode !== null) {
        return;
      }
      child.kill("SIGTERM");
      await new Promise((resolve) => {
        const timeout = setTimeout(() => {
          child.kill("SIGKILL");
          resolve(undefined);
        }, 5_000);
        child.once("exit", () => {
          clearTimeout(timeout);
          resolve(undefined);
        });
      });
    },
  };
}

export async function startMockTrustedServer(params: {
  port: number;
  authorize: (
    request: unknown,
  ) => Promise<{ status?: number; body: unknown }> | { status?: number; body: unknown };
  confirm?: (
    request: unknown,
  ) => Promise<{ status?: number; body: unknown }> | { status?: number; body: unknown };
  complete?: (
    request: unknown,
  ) => Promise<{ status?: number; body: unknown }> | { status?: number; body: unknown };
}): Promise<TrustedBackendHandle> {
  const { createServer } = await import("node:http");
  const stdout: string[] = [];
  const stderr: string[] = [];
  const server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", `http://127.0.0.1:${params.port}`);
      const chunks: Buffer[] = [];
      for await (const chunk of req) {
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      }
      const raw = Buffer.concat(chunks).toString("utf8");
      const body = raw.trim() ? JSON.parse(raw) : {};
      if (req.method === "GET" && url.pathname === "/healthz") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true }));
        return;
      }
      if (req.method === "POST" && url.pathname === "/v1/trusted/authorize") {
        const response = await params.authorize(body);
        res.writeHead(response.status ?? 200, { "content-type": "application/json" });
        res.end(typeof response.body === "string" ? response.body : JSON.stringify(response.body));
        return;
      }
      if (req.method === "POST" && url.pathname === "/v1/trusted/complete") {
        const response = params.complete
          ? await params.complete(body)
          : { status: 200, body: { ok: true } };
        res.writeHead(response.status ?? 200, { "content-type": "application/json" });
        res.end(typeof response.body === "string" ? response.body : JSON.stringify(response.body));
        return;
      }
      if (req.method === "POST" && url.pathname === "/v1/trusted/confirm") {
        const response = params.confirm
          ? await params.confirm(body)
          : { status: 200, body: { ok: false, status: "denied" } };
        res.writeHead(response.status ?? 200, { "content-type": "application/json" });
        res.end(typeof response.body === "string" ? response.body : JSON.stringify(response.body));
        return;
      }
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "not_found" }));
    } catch (error) {
      stderr.push(error instanceof Error ? error.stack || error.message : String(error));
      res.writeHead(500, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "internal_error" }));
    }
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(params.port, "127.0.0.1", () => resolve(undefined));
  });
  const baseUrl = `http://127.0.0.1:${params.port}`;
  await waitForHttpOk(`${baseUrl}/healthz`);
  stdout.push(`mock trusted server listening on ${baseUrl}`);
  return {
    baseUrl,
    stdout,
    stderr,
    stop: async () => {
      await new Promise((resolve) => server.close(() => resolve(undefined)));
    },
  };
}

export async function runExecThroughTrustedIsolation(params: {
  harness: TrustedIsolationHarness;
  command: string;
  runId: string;
  toolCallId: string;
  tamperedCommand?: string;
  overrideArgs?: Record<string, unknown>;
}): Promise<{
  hook:
    | { blocked: true; reason: string }
    | {
        blocked: false;
        params: Record<string, unknown>;
      };
  result?: AgentToolResult<unknown>;
  error?: Error;
}> {
  const hook = await authorizeExecToolCall({
    harness: params.harness,
    command: params.command,
    runId: params.runId,
    toolCallId: params.toolCallId,
    overrideArgs: params.overrideArgs,
  });
  if (hook.blocked) {
    return { hook };
  }
  const execution = await executeAuthorizedExec({
    harness: params.harness,
    authorizedParams: hook.params,
    runId: params.runId,
    toolCallId: params.toolCallId,
    tamperedCommand: params.tamperedCommand,
  });
  return { hook, ...execution };
}

export async function runMeasuredExecThroughTrustedIsolation(params: {
  harness: TrustedIsolationHarness;
  command: string;
  runId: string;
  toolCallId: string;
  overrideArgs?: Record<string, unknown>;
}): Promise<{
  hook:
    | { blocked: true; reason: string }
    | {
        blocked: false;
        params: Record<string, unknown>;
      };
  result?: AgentToolResult<unknown>;
  error?: Error;
  authorizeMs: number;
  executeMs: number;
  completeMs: number;
  e2eMs: number;
}> {
  return await withTrustedIsolationEnv(params.harness, async () => {
    const { runBeforeToolCallHook } =
      await import("../../../src/agents/pi-tools.before-tool-call.ts");
    const { createExecTool } = await import("../../../src/agents/bash-tools.exec.ts");
    const { finalizeTrustedIsolationToolCall } =
      await import("../../../src/security/trusted-isolation/runtime.ts");

    const e2eStart = performance.now();
    const authorizeStart = performance.now();
    const hook = await runBeforeToolCallHook({
      toolName: "exec",
      params: {
        command: params.command,
        workdir: params.harness.workspaceDir,
        ...(params.overrideArgs ?? {}),
      },
      toolCallId: params.toolCallId,
      ctx: {
        agentId: params.harness.agentId,
        sessionKey: params.harness.sessionKey,
        runId: params.runId,
      },
    });
    const authorizeMs = performance.now() - authorizeStart;
    if (hook.blocked) {
      return {
        hook,
        authorizeMs,
        executeMs: 0,
        completeMs: 0,
        e2eMs: performance.now() - e2eStart,
      };
    }

    const execTool = createExecTool({
      agentId: params.harness.agentId,
      sessionKey: params.harness.sessionKey,
      cwd: params.harness.workspaceDir,
      host: "gateway",
      security: "full",
      ask: "off",
      allowBackground: false,
    });

    let result: AgentToolResult<unknown> | undefined;
    let error: Error | undefined;
    const executeStart = performance.now();
    try {
      result = await execTool.execute(params.toolCallId, hook.params, undefined);
    } catch (caught) {
      error = caught instanceof Error ? caught : new Error(String(caught));
    }
    const executeMs = performance.now() - executeStart;

    const completeStart = performance.now();
    await finalizeTrustedIsolationToolCall({
      toolName: "exec",
      toolCallId: params.toolCallId,
      runId: params.runId,
      isError: Boolean(error),
      result: error ?? result,
    });
    const completeMs = performance.now() - completeStart;

    return {
      hook,
      result,
      error,
      authorizeMs,
      executeMs,
      completeMs,
      e2eMs: performance.now() - e2eStart,
    };
  });
}

export async function authorizeExecToolCall(params: {
  harness: TrustedIsolationHarness;
  command: string;
  runId: string;
  toolCallId: string;
  overrideArgs?: Record<string, unknown>;
}): Promise<
  | { blocked: true; reason: string }
  | {
      blocked: false;
      params: Record<string, unknown>;
    }
> {
  return await withTrustedIsolationEnv(params.harness, async () => {
    const { runBeforeToolCallHook } =
      await import("../../../src/agents/pi-tools.before-tool-call.ts");
    return await runBeforeToolCallHook({
      toolName: "exec",
      params: {
        command: params.command,
        workdir: params.harness.workspaceDir,
        ...(params.overrideArgs ?? {}),
      },
      toolCallId: params.toolCallId,
      ctx: {
        agentId: params.harness.agentId,
        sessionKey: params.harness.sessionKey,
        runId: params.runId,
      },
    });
  });
}

export async function executeAuthorizedExec(params: {
  harness: TrustedIsolationHarness;
  authorizedParams: Record<string, unknown>;
  runId: string;
  toolCallId: string;
  tamperedCommand?: string;
}): Promise<{
  result?: AgentToolResult<unknown>;
  error?: Error;
}> {
  return await withTrustedIsolationEnv(params.harness, async () => {
    const { createExecTool } = await import("../../../src/agents/bash-tools.exec.ts");
    const { finalizeTrustedIsolationToolCall } =
      await import("../../../src/security/trusted-isolation/runtime.ts");
    const execTool = createExecTool({
      agentId: params.harness.agentId,
      sessionKey: params.harness.sessionKey,
      cwd: params.harness.workspaceDir,
      host: "gateway",
      security: "full",
      ask: "off",
      allowBackground: false,
    });

    try {
      const result = await execTool.execute(
        params.toolCallId,
        {
          ...params.authorizedParams,
          ...(params.tamperedCommand ? { command: params.tamperedCommand } : {}),
        },
        undefined,
      );
      await finalizeTrustedIsolationToolCall({
        toolName: "exec",
        toolCallId: params.toolCallId,
        runId: params.runId,
        isError: false,
        result,
      });
      return { result };
    } catch (error) {
      const normalizedError = error instanceof Error ? error : new Error(String(error));
      await finalizeTrustedIsolationToolCall({
        toolName: "exec",
        toolCallId: params.toolCallId,
        runId: params.runId,
        isError: true,
        result: normalizedError,
      });
      return { error: normalizedError };
    }
  });
}

export async function readJsonlRecords(filePath: string): Promise<Array<Record<string, unknown>>> {
  const raw = await fs.readFile(filePath, "utf8");
  return raw
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => JSON.parse(line) as Record<string, unknown>);
}

export async function readTrustedEvidenceSummary(filePath: string): Promise<{
  ok: boolean;
  errors: string[];
  summary: {
    entryCount: number;
    reqIds: number;
    authorizePairs: number;
  };
}> {
  const { validateTrustedEvidenceFile } =
    await import("../../../src/security/trusted-layer/evidence.ts");
  return await validateTrustedEvidenceFile(filePath);
}

export async function assertFileMissing(filePath: string): Promise<void> {
  try {
    await fs.access(filePath);
    assert.fail(`expected file to be absent: ${filePath}`);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
      return;
    }
    throw error;
  }
}
