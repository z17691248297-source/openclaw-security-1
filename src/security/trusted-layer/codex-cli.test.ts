import { beforeEach, describe, expect, it, vi } from "vitest";

const hoisted = vi.hoisted(() => ({
  enforceTrustedIsolationBeforeToolCall: vi.fn(),
  finalizeTrustedIsolationToolCall: vi.fn(),
  resolveTrustedIsolationConfig: vi.fn(),
  verifyAuthorizedExecScope: vi.fn(),
}));

vi.mock("../trusted-isolation/runtime.js", () => ({
  enforceTrustedIsolationBeforeToolCall: (...args: unknown[]) =>
    hoisted.enforceTrustedIsolationBeforeToolCall(...args),
  finalizeTrustedIsolationToolCall: (...args: unknown[]) =>
    hoisted.finalizeTrustedIsolationToolCall(...args),
}));

vi.mock("../trusted-isolation/config.js", () => ({
  resolveTrustedIsolationConfig: (...args: unknown[]) =>
    hoisted.resolveTrustedIsolationConfig(...args),
}));

vi.mock("./scope.js", () => ({
  verifyAuthorizedExecScope: (...args: unknown[]) => hoisted.verifyAuthorizedExecScope(...args),
}));

describe("trusted codex-cli bridge", () => {
  beforeEach(() => {
    hoisted.enforceTrustedIsolationBeforeToolCall.mockReset();
    hoisted.finalizeTrustedIsolationToolCall.mockReset();
    hoisted.resolveTrustedIsolationConfig.mockReset();
    hoisted.verifyAuthorizedExecScope.mockReset();

    hoisted.resolveTrustedIsolationConfig.mockReturnValue({
      enabled: true,
      verifyMode: "none",
    });
    hoisted.enforceTrustedIsolationBeforeToolCall.mockResolvedValue({
      blocked: false,
      params: {
        __openclawTrusted: {
          token: "scope-token",
          reqId: "req-1",
          sid: "session-1",
          action: "exec",
          object: "echo hi",
          normalizedScopeDigest: "digest-1",
        },
      },
    });
    hoisted.finalizeTrustedIsolationToolCall.mockResolvedValue(undefined);
    hoisted.verifyAuthorizedExecScope.mockReturnValue({
      reqId: "req-1",
      sid: "session-1",
    });
  });

  it("normalizes Codex shell transport commands", async () => {
    const { normalizeCodexCommandExecutionCommand } = await import("./codex-cli.js");

    expect(normalizeCodexCommandExecutionCommand("/bin/bash -lc 'printf hi > out.txt'")).toBe(
      "printf hi > out.txt",
    );
    expect(normalizeCodexCommandExecutionCommand("python -c 'print(1)'")).toBe(
      "python -c 'print(1)'",
    );
  });

  it("authorizes and finalizes command_execution items", async () => {
    const { createTrustedCodexCliStreamBridge } = await import("./codex-cli.js");
    const cancelRun = vi.fn();
    const bridge = createTrustedCodexCliStreamBridge({
      providerId: "codex-cli",
      sessionId: "session-1",
      sessionKey: "agent:main:session-1",
      runId: "run-1",
      workspaceDir: "/tmp/workspace",
      cancelRun,
    });

    bridge.onStdout(
      `${JSON.stringify({
        type: "item.started",
        item: {
          id: "item_0",
          type: "command_execution",
          command: "/bin/bash -lc 'echo hi'",
          status: "in_progress",
        },
      })}\n`,
    );
    bridge.onStdout(
      `${JSON.stringify({
        type: "item.completed",
        item: {
          id: "item_0",
          type: "command_execution",
          command: "/bin/bash -lc 'echo hi'",
          aggregated_output: "hi\n",
          exit_code: 0,
          status: "completed",
        },
      })}\n`,
    );

    await bridge.waitForSettled();

    expect(hoisted.enforceTrustedIsolationBeforeToolCall).toHaveBeenCalledWith(
      expect.objectContaining({
        toolName: "exec",
        toolCallId: "item_0",
        inputParams: {
          command: "echo hi",
          workdir: "/tmp/workspace",
        },
      }),
    );
    expect(hoisted.verifyAuthorizedExecScope).toHaveBeenCalledTimes(2);
    expect(hoisted.finalizeTrustedIsolationToolCall).toHaveBeenCalledWith(
      expect.objectContaining({
        toolName: "exec",
        toolCallId: "item_0",
        runId: "run-1",
        isError: false,
      }),
    );
    expect(cancelRun).not.toHaveBeenCalled();
    expect(bridge.getFailure()).toBeUndefined();
  });

  it("fails closed when trusted authorize blocks the command", async () => {
    hoisted.enforceTrustedIsolationBeforeToolCall.mockResolvedValueOnce({
      blocked: true,
      reason: "trusted authorization rejected",
    });
    const { createTrustedCodexCliStreamBridge } = await import("./codex-cli.js");
    const cancelRun = vi.fn();
    const bridge = createTrustedCodexCliStreamBridge({
      providerId: "codex-cli",
      sessionId: "session-1",
      runId: "run-1",
      workspaceDir: "/tmp/workspace",
      cancelRun,
    });

    bridge.onStdout(
      `${JSON.stringify({
        type: "item.started",
        item: {
          id: "item_deny",
          type: "command_execution",
          command: "/bin/bash -lc 'echo denied'",
          status: "in_progress",
        },
      })}\n`,
    );

    await bridge.waitForSettled();

    expect(cancelRun).toHaveBeenCalledWith(
      expect.objectContaining({ message: "trusted authorization rejected" }),
    );
    expect(hoisted.finalizeTrustedIsolationToolCall).not.toHaveBeenCalled();
    expect(bridge.getFailure()).toEqual(
      expect.objectContaining({ message: "trusted authorization rejected" }),
    );
  });
});
