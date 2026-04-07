import { describe, expect, it } from "vitest";
import { buildTrustedIsolationOperation, buildTrustedOperationRequest } from "./request.js";

describe("trusted request builder", () => {
  it("marks compound shell commands as shell-exact requests", () => {
    const operation = buildTrustedIsolationOperation({
      toolName: "exec",
      inputParams: {
        command:
          "if [ -f HEARTBEAT.md ]; then sed -n '1,240p' HEARTBEAT.md; else echo '__NO_HEARTBEAT__'; fi",
        workdir: "/home/zqw/openclaw",
      },
      context: {
        agentId: "main",
        sessionKey: "agent:main:main",
        runId: "run-1",
      },
      toolCallId: "tc-1",
    });

    const request = buildTrustedOperationRequest({
      operation,
      sequence: 1,
      ttlMs: 5_000,
      reqId: "req-1",
      issuedAtMs: 1,
    });

    expect(request.scope.exec).toMatchObject({
      matchMode: "shell-exact",
      rawCommand:
        "if [ -f HEARTBEAT.md ]; then sed -n '1,240p' HEARTBEAT.md; else echo '__NO_HEARTBEAT__'; fi",
      command: "shell-compound",
      args: [],
      cwd: "/home/zqw/openclaw",
    });
  });

  it("keeps ordinary exec commands as exact argv-bound requests", () => {
    const operation = buildTrustedIsolationOperation({
      toolName: "exec",
      inputParams: {
        command: "echo wa-trusted",
        workdir: "/home/zqw/openclaw",
      },
    });

    const request = buildTrustedOperationRequest({
      operation,
      sequence: 1,
      ttlMs: 5_000,
      reqId: "req-2",
      issuedAtMs: 1,
    });

    expect(request.scope.exec).toMatchObject({
      matchMode: "exact",
      rawCommand: "echo wa-trusted",
      command: "echo",
      args: ["wa-trusted"],
    });
  });
});
