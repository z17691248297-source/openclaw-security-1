import { createSubsystemLogger } from "../../logging/subsystem.js";
import { splitShellArgs } from "../../utils/shell-argv.js";
import { resolveTrustedIsolationConfig } from "../trusted-isolation/config.js";
import {
  enforceTrustedIsolationBeforeToolCall,
  finalizeTrustedIsolationToolCall,
} from "../trusted-isolation/runtime.js";
import { verifyAuthorizedExecScope } from "./scope.js";

const log = createSubsystemLogger("security/trusted-isolation");

type CommandExecutionItem = {
  id?: string;
  type?: string;
  command?: string;
  aggregated_output?: string;
  exit_code?: number | null;
  status?: string;
};

type CommandExecutionState = {
  toolCallId: string;
  rawCommand: string;
  normalizedCommand: string;
  authorizationFinished: boolean;
  blocked: boolean;
  finalized: boolean;
  adjustedParams?: Record<string, unknown>;
  completion?: CommandExecutionItem;
};

type TrustedCodexCliStreamBridge = {
  onStdout: (chunk: string) => void;
  getFailure: () => Error | undefined;
  waitForSettled: () => Promise<void>;
};

type TrustedCodexCliStreamBridgeParams = {
  providerId: string;
  agentId?: string;
  sessionId: string;
  sessionKey?: string;
  runId: string;
  workspaceDir: string;
  cancelRun: (error: Error) => void;
};

class TrustedCliAbortError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TrustedCliAbortError";
  }
}

function createNoopBridge(): TrustedCodexCliStreamBridge {
  return {
    onStdout: () => {},
    getFailure: () => undefined,
    waitForSettled: async () => {},
  };
}

function toError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

function trackTask(tasks: Set<Promise<void>>, task: Promise<void>): void {
  let tracked: Promise<void>;
  tracked = task.finally(() => {
    tasks.delete(tracked);
  });
  tasks.add(tracked);
}

function isCommandExecutionItem(value: unknown): value is CommandExecutionItem {
  return Boolean(
    value &&
    typeof value === "object" &&
    (value as CommandExecutionItem).type === "command_execution" &&
    typeof (value as CommandExecutionItem).id === "string" &&
    typeof (value as CommandExecutionItem).command === "string",
  );
}

function unwrapCodexShellTransport(rawCommand: string): string {
  const parsed = splitShellArgs(rawCommand.trim());
  if (!parsed || parsed.length < 3) {
    return rawCommand.trim();
  }
  const shellPath = parsed[0] ?? "";
  const shellBase = shellPath.split("/").at(-1) ?? shellPath;
  const mode = parsed[1] ?? "";
  const nestedCommand = parsed[2] ?? "";
  if (!["bash", "sh", "zsh"].includes(shellBase)) {
    return rawCommand.trim();
  }
  if (!/^-[^-]*c/.test(mode) || !nestedCommand.trim()) {
    return rawCommand.trim();
  }
  return nestedCommand.trim();
}

function buildCompletionResult(item: CommandExecutionItem): {
  isError: boolean;
  result: Record<string, unknown>;
} {
  const exitCode = typeof item.exit_code === "number" ? item.exit_code : null;
  const output = typeof item.aggregated_output === "string" ? item.aggregated_output : "";
  const command = typeof item.command === "string" ? item.command : "";
  const payload = {
    command: unwrapCodexShellTransport(command),
    observedCommand: command,
    aggregatedOutput: output,
    exitCode,
    status: item.status,
  };
  if (exitCode !== null && exitCode !== 0) {
    return {
      isError: true,
      result: {
        ...payload,
        error: output || `command exited with code ${exitCode}`,
      },
    };
  }
  return {
    isError: false,
    result: payload,
  };
}

export function normalizeCodexCommandExecutionCommand(rawCommand: string): string {
  return unwrapCodexShellTransport(rawCommand);
}

export function createTrustedCodexCliStreamBridge(
  params: TrustedCodexCliStreamBridgeParams,
): TrustedCodexCliStreamBridge {
  const trustedConfig = resolveTrustedIsolationConfig(params.agentId);
  if (!trustedConfig.enabled || params.providerId !== "codex-cli") {
    return createNoopBridge();
  }

  const commandStates = new Map<string, CommandExecutionState>();
  const tasks = new Set<Promise<void>>();
  const expectedSid = params.sessionKey ?? params.sessionId;
  let pendingBuffer = "";
  let failure: Error | undefined;

  const failClosed = (error: unknown): void => {
    if (failure) {
      return;
    }
    failure = toError(error);
    params.cancelRun(failure);
  };

  const finalizeInterruptedCommand = async (state: CommandExecutionState): Promise<void> => {
    if (!state.authorizationFinished || state.blocked || state.finalized || !state.adjustedParams) {
      return;
    }
    state.finalized = true;
    commandStates.delete(state.toolCallId);
    await finalizeTrustedIsolationToolCall({
      toolName: "exec",
      toolCallId: state.toolCallId,
      runId: params.runId,
      isError: true,
      result: new Error("codex command execution interrupted before completion"),
    });
  };

  const finalizeAuthorizedCommand = async (state: CommandExecutionState): Promise<void> => {
    if (state.finalized || state.blocked || !state.adjustedParams || !state.completion) {
      return;
    }
    state.finalized = true;
    commandStates.delete(state.toolCallId);

    const completedCommand = normalizeCodexCommandExecutionCommand(
      state.completion.command ?? state.rawCommand,
    );
    try {
      void verifyAuthorizedExecScope({
        args: state.adjustedParams,
        command: completedCommand,
        workdir: params.workspaceDir,
        expectedSid,
        config: trustedConfig,
      });
    } catch (error) {
      const trustedError = toError(error);
      await finalizeTrustedIsolationToolCall({
        toolName: "exec",
        toolCallId: state.toolCallId,
        runId: params.runId,
        isError: true,
        result: trustedError,
      });
      failClosed(trustedError);
      return;
    }

    const completion = buildCompletionResult(state.completion);
    await finalizeTrustedIsolationToolCall({
      toolName: "exec",
      toolCallId: state.toolCallId,
      runId: params.runId,
      isError: completion.isError,
      result: completion.result,
    });
  };

  const authorizeCommand = async (state: CommandExecutionState): Promise<void> => {
    const authorization = await enforceTrustedIsolationBeforeToolCall({
      toolName: "exec",
      inputParams: {
        command: state.normalizedCommand,
        workdir: params.workspaceDir,
      },
      context: {
        agentId: params.agentId,
        sessionId: params.sessionId,
        sessionKey: params.sessionKey,
        runId: params.runId,
      },
      toolCallId: state.toolCallId,
    });
    state.authorizationFinished = true;

    if (authorization.blocked) {
      state.blocked = true;
      commandStates.delete(state.toolCallId);
      failClosed(new TrustedCliAbortError(authorization.reason));
      return;
    }

    state.adjustedParams = authorization.params;
    try {
      void verifyAuthorizedExecScope({
        args: authorization.params,
        command: state.normalizedCommand,
        workdir: params.workspaceDir,
        expectedSid,
        config: trustedConfig,
      });
    } catch (error) {
      const trustedError = toError(error);
      state.blocked = true;
      commandStates.delete(state.toolCallId);
      await finalizeTrustedIsolationToolCall({
        toolName: "exec",
        toolCallId: state.toolCallId,
        runId: params.runId,
        isError: true,
        result: trustedError,
      });
      failClosed(trustedError);
      return;
    }

    if (state.completion) {
      await finalizeAuthorizedCommand(state);
    }
  };

  const handleCommandStart = (item: CommandExecutionItem): void => {
    const toolCallId = item.id?.trim();
    const rawCommand = item.command?.trim();
    if (!toolCallId || !rawCommand || commandStates.has(toolCallId)) {
      return;
    }
    const state: CommandExecutionState = {
      toolCallId,
      rawCommand,
      normalizedCommand: normalizeCodexCommandExecutionCommand(rawCommand),
      authorizationFinished: false,
      blocked: false,
      finalized: false,
    };
    commandStates.set(toolCallId, state);
    trackTask(tasks, authorizeCommand(state));
  };

  const handleCommandCompletion = (item: CommandExecutionItem): void => {
    const toolCallId = item.id?.trim();
    if (!toolCallId) {
      return;
    }
    const state = commandStates.get(toolCallId);
    if (!state) {
      return;
    }
    state.completion = item;
    if (state.authorizationFinished) {
      trackTask(tasks, finalizeAuthorizedCommand(state));
    }
  };

  const handleParsedLine = (line: string): void => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      return;
    }
    if (!parsed || typeof parsed !== "object") {
      return;
    }
    const type = (parsed as { type?: unknown }).type;
    if (type === "item.started") {
      const item = (parsed as { item?: unknown }).item;
      if (isCommandExecutionItem(item)) {
        handleCommandStart(item);
      }
      return;
    }
    if (type === "item.completed") {
      const item = (parsed as { item?: unknown }).item;
      if (isCommandExecutionItem(item)) {
        handleCommandCompletion(item);
      }
    }
  };

  return {
    onStdout(chunk: string) {
      pendingBuffer += chunk;
      while (true) {
        const newlineIndex = pendingBuffer.indexOf("\n");
        if (newlineIndex < 0) {
          break;
        }
        const line = pendingBuffer.slice(0, newlineIndex).trim();
        pendingBuffer = pendingBuffer.slice(newlineIndex + 1);
        if (!line) {
          continue;
        }
        try {
          handleParsedLine(line);
        } catch (error) {
          log.warn(`trusted codex-cli stream hook failed: ${String(error)}`);
        }
      }
    },

    getFailure() {
      return failure;
    },

    async waitForSettled() {
      while (tasks.size > 0) {
        await Promise.all([...tasks]);
      }
      const interrupted = [...commandStates.values()];
      await Promise.all(interrupted.map((state) => finalizeInterruptedCommand(state)));
    },
  };
}
