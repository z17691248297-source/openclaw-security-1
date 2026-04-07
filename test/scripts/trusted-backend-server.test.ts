import { spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs/promises";
import { createServer } from "node:net";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

const cleanupDirs: string[] = [];
const cleanupChildren: ChildProcess[] = [];

afterEach(async () => {
  await Promise.all(
    cleanupChildren.splice(0).map(async (child) => {
      if (child.exitCode !== null || child.signalCode !== null) {
        return;
      }
      child.kill("SIGTERM");
      await new Promise((resolve) => child.once("exit", () => resolve(undefined)));
    }),
  );
  await Promise.all(
    cleanupDirs.splice(0).map((dir) => fs.rm(dir, { recursive: true, force: true })),
  );
});

async function reservePort(): Promise<number> {
  const server = createServer();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve(undefined));
  });
  const address = server.address();
  await new Promise((resolve) => server.close(() => resolve(undefined)));
  if (!address || typeof address !== "object") {
    throw new Error("failed to reserve port");
  }
  return address.port;
}

async function waitForHealthz(baseUrl: string): Promise<void> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    try {
      const response = await fetch(`${baseUrl}/healthz`);
      if (response.ok) {
        return;
      }
    } catch {
      // Retry until ready.
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`backend did not become healthy at ${baseUrl}`);
}

function startBackend(params: { port: number; eventsFile: string; rootDir: string }): ChildProcess {
  const child = spawn(
    process.execPath,
    [path.resolve("external/openclaw-trusted-backend/server.mjs")],
    {
      cwd: params.rootDir,
      env: {
        ...process.env,
        TRUSTED_BACKEND_HOST: "127.0.0.1",
        TRUSTED_BACKEND_PORT: String(params.port),
        TRUSTED_VERIFY_MODE: "hmac-sha256",
        TRUSTED_HMAC_KEY: "test-shared-secret",
        TRUSTED_BACKEND_EVENTS_FILE: params.eventsFile,
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  cleanupChildren.push(child);
  return child;
}

function startBackendWithEnv(params: {
  port: number;
  eventsFile: string;
  rootDir: string;
  extraEnv?: Record<string, string>;
}): ChildProcess {
  const child = spawn(
    process.execPath,
    [path.resolve("external/openclaw-trusted-backend/server.mjs")],
    {
      cwd: params.rootDir,
      env: {
        ...process.env,
        TRUSTED_BACKEND_HOST: "127.0.0.1",
        TRUSTED_BACKEND_PORT: String(params.port),
        TRUSTED_VERIFY_MODE: "hmac-sha256",
        TRUSTED_HMAC_KEY: "test-shared-secret",
        TRUSTED_BACKEND_EVENTS_FILE: params.eventsFile,
        ...(params.extraEnv ?? {}),
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  cleanupChildren.push(child);
  return child;
}

function buildAuthorizeRequest(reqId: string) {
  return {
    version: 1,
    reqId,
    sid: "sid-server-test",
    seq: 1,
    ttlMs: 5_000,
    issuedAtMs: Date.now(),
    toolName: "exec",
    action: "exec",
    object: "echo continuity",
    scope: {
      action: "exec",
      target: "echo continuity",
      exec: {
        matchMode: "exact",
        rawCommand: "echo continuity",
        command: "echo",
        args: ["continuity"],
        cwd: "/tmp",
      },
      restrictions: {},
    },
    context: {
      workdir: "/tmp",
      workspaceRoot: "/tmp",
    },
    level: "L1",
    normalizedScopeDigest: `digest-${reqId}`,
    requestDigest: `request-${reqId}`,
  };
}

describe("trusted backend server", () => {
  it("restores the previous entry hash across restarts", async () => {
    const rootDir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-trusted-backend-server-"));
    cleanupDirs.push(rootDir);
    const eventsFile = path.join(rootDir, "trusted-backend-events.jsonl");

    const port1 = await reservePort();
    const baseUrl1 = `http://127.0.0.1:${port1}`;
    const child1 = startBackend({ port: port1, eventsFile, rootDir });
    await waitForHealthz(baseUrl1);
    await fetch(`${baseUrl1}/v1/trusted/authorize`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(buildAuthorizeRequest("req-1")),
    });
    child1.kill("SIGTERM");
    await new Promise((resolve) => child1.once("exit", () => resolve(undefined)));

    const firstRecord = JSON.parse(
      (await fs.readFile(eventsFile, "utf8")).trim().split("\n")[0] ?? "{}",
    ) as {
      entryHash?: string;
    };
    expect(typeof firstRecord.entryHash).toBe("string");

    const port2 = await reservePort();
    const baseUrl2 = `http://127.0.0.1:${port2}`;
    startBackend({ port: port2, eventsFile, rootDir });
    await waitForHealthz(baseUrl2);
    await fetch(`${baseUrl2}/v1/trusted/authorize`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(buildAuthorizeRequest("req-2")),
    });

    const lines = (await fs.readFile(eventsFile, "utf8"))
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean);
    const secondRecord = JSON.parse(lines[1] ?? "{}") as {
      prevHash?: string;
    };
    expect(secondRecord.prevHash).toBe(firstRecord.entryHash);
  });

  it("issues and redeems trusted confirmation challenges for duc decisions", async () => {
    const rootDir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-trusted-backend-confirm-"));
    cleanupDirs.push(rootDir);
    const eventsFile = path.join(rootDir, "trusted-backend-events.jsonl");
    const port = await reservePort();
    const baseUrl = `http://127.0.0.1:${port}`;
    startBackend({ port, eventsFile, rootDir });
    await waitForHealthz(baseUrl);

    const authorizeResponse = await fetch(`${baseUrl}/v1/trusted/authorize`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        ...buildAuthorizeRequest("req-confirm"),
        object: "tar -czf workspace.tgz docs",
        scope: {
          action: "exec",
          target: "tar -czf workspace.tgz docs",
          exec: {
            matchMode: "exact",
            rawCommand: "tar -czf workspace.tgz docs",
            command: "tar",
            args: ["-czf", "workspace.tgz", "docs"],
            cwd: "/tmp",
          },
          restrictions: {},
        },
      }),
    }).then((response) => response.json());

    expect(authorizeResponse.decision).toBe("duc");
    expect(authorizeResponse.confirmation).toEqual(
      expect.objectContaining({
        confirmationRequestId: expect.any(String),
        challengeToken: expect.any(String),
        executionMode: "ree-constrained",
      }),
    );

    const confirmResponse = await fetch(`${baseUrl}/v1/trusted/confirm`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        confirmationRequestId: authorizeResponse.confirmation.confirmationRequestId,
        challengeToken: authorizeResponse.confirmation.challengeToken,
        operatorId: "tester",
        decision: "approve",
      }),
    }).then((response) => response.json());

    expect(confirmResponse).toEqual(
      expect.objectContaining({
        ok: true,
        status: "approved",
        decision: "dia",
        executionMode: "ree-constrained",
        operatorId: "tester",
        scopeToken: expect.any(String),
      }),
    );

    const lines = (await fs.readFile(eventsFile, "utf8"))
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => JSON.parse(line) as { event?: string });
    expect(lines.map((entry) => entry.event)).toEqual(["authorize", "confirm"]);
  });

  it("exposes local-tdx guest identity and attestation summary", async () => {
    const rootDir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-trusted-backend-guest-"));
    cleanupDirs.push(rootDir);
    const eventsFile = path.join(rootDir, "trusted-backend-events.jsonl");
    const attestationFile = path.join(rootDir, "tdx-attestation.json");
    await fs.writeFile(
      attestationFile,
      JSON.stringify({
        guestId: "tdx-guest:test",
        serviceName: "openclaw-trusted-backend",
        measurement: "a1".repeat(32),
        quoteFormat: "tdx-quote-v4",
        quoteBase64: Buffer.from("quote-bytes").toString("base64"),
      }),
      "utf8",
    );
    const port = await reservePort();
    const baseUrl = `http://127.0.0.1:${port}`;
    startBackendWithEnv({
      port,
      eventsFile,
      rootDir,
      extraEnv: {
        TRUSTED_BACKEND_ADAPTOR: "local-tdx",
        TRUSTED_TDX_GUEST_ID: "tdx-guest:test",
        TRUSTED_TDX_MEASUREMENT: "a1".repeat(32),
        TRUSTED_TDX_ATTESTATION_FILE: attestationFile,
      },
    });
    await waitForHealthz(baseUrl);

    const health = await fetch(`${baseUrl}/healthz`).then((response) => response.json());
    expect(health.guest).toEqual(
      expect.objectContaining({
        platform: "tdx",
        guestId: "tdx-guest:test",
        attestationMode: "file",
        attestationReady: true,
        measurement: "a1".repeat(32),
      }),
    );

    const guestInfo = await fetch(`${baseUrl}/v1/trusted/guest?attest=1`).then((response) =>
      response.json(),
    );
    expect(guestInfo).toEqual(
      expect.objectContaining({
        ok: true,
        adaptor: "local-tdx",
        platform: "tdx",
        guest: expect.objectContaining({
          guestId: "tdx-guest:test",
          attestationMode: "file",
        }),
        attestation: expect.objectContaining({
          guestId: "tdx-guest:test",
          attestationMode: "file",
          quoteFormat: "tdx-quote-v4",
          quoteBytes: "quote-bytes".length,
          quoteSha256: expect.any(String),
          requestBinding: expect.objectContaining({
            phase: "guest-info",
          }),
        }),
      }),
    );

    const authorize = await fetch(`${baseUrl}/v1/trusted/authorize`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(buildAuthorizeRequest("req-guest-proof")),
    }).then((response) => response.json());
    expect(authorize.evidence?.proof?.tdxGuest).toEqual(
      expect.objectContaining({
        guestId: "tdx-guest:test",
        attestationMode: "file",
        quoteSha256: expect.any(String),
        requestBinding: expect.objectContaining({
          phase: "authorize",
          reqId: "req-guest-proof",
        }),
      }),
    );
  });
});
