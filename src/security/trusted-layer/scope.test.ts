import { describe, expect, it } from "vitest";
import { resolveTrustedIsolationConfig } from "../trusted-isolation/config.js";
import {
  buildTrustedIsolationOperation,
  buildTrustedOperationRequest,
  buildTrustedScopeEnvelope,
} from "./request.js";
import { applyTrustedScopeToParams, verifyAuthorizedExecScope } from "./scope.js";

function toBase64Url(input: string): string {
  return Buffer.from(input, "utf8")
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function buildShellExactArgs(rawCommand: string) {
  const operation = buildTrustedIsolationOperation({
    toolName: "exec",
    inputParams: {
      command: rawCommand,
      workdir: "/home/zqw/openclaw",
    },
    context: {
      sessionKey: "agent:main:main",
    },
    toolCallId: "tc-shell",
  });
  const request = buildTrustedOperationRequest({
    operation,
    sequence: 1,
    ttlMs: 5_000,
    reqId: "req-shell",
    issuedAtMs: Date.now(),
  });
  const tokenPayload = {
    version: 1,
    reqId: request.reqId,
    sid: request.sid,
    action: request.action,
    object: request.object,
    scope: request.scope,
    normalizedScopeDigest: request.normalizedScopeDigest,
    issuedAtMs: request.issuedAtMs,
    expiresAtMs: request.issuedAtMs + request.ttlMs,
  };
  const token = `${toBase64Url(JSON.stringify(tokenPayload))}.ignored`;
  return applyTrustedScopeToParams({
    inputParams: {
      command: rawCommand,
      workdir: "/home/zqw/openclaw",
    },
    envelope: buildTrustedScopeEnvelope({
      request,
      scopeToken: token,
      level: "L2",
    }),
  });
}

describe("trusted exec scope verification", () => {
  it("accepts shell-exact commands when the raw command matches exactly", () => {
    const command =
      "if [ -f HEARTBEAT.md ]; then sed -n '1,240p' HEARTBEAT.md; else echo '__NO_HEARTBEAT__'; fi";
    const config = {
      ...resolveTrustedIsolationConfig(),
      enabled: true,
      verifyMode: "none" as const,
      requireScopeToken: true,
    };
    expect(() =>
      verifyAuthorizedExecScope({
        args: buildShellExactArgs(command),
        command,
        workdir: "/home/zqw/openclaw",
        expectedSid: "agent:main:main",
        config,
      }),
    ).not.toThrow();
  });

  it("rejects shell-exact commands when the raw command changes", () => {
    const args = buildShellExactArgs("if [ -f HEARTBEAT.md ]; then cat HEARTBEAT.md; fi");
    const config = {
      ...resolveTrustedIsolationConfig(),
      enabled: true,
      verifyMode: "none" as const,
      requireScopeToken: true,
    };
    expect(() =>
      verifyAuthorizedExecScope({
        args,
        command: "if [ -f HEARTBEAT.md ]; then echo hacked; fi",
        workdir: "/home/zqw/openclaw",
        expectedSid: "agent:main:main",
        config,
      }),
    ).toThrow(/trusted scope violation/i);
  });
});
