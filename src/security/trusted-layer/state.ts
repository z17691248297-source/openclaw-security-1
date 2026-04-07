import { digestTrustedValue } from "./digest.js";
import type { TrustedPendingExecution } from "./types.js";

const pendingExecutions = new Map<string, TrustedPendingExecution>();

function buildPendingKey(runId: string | undefined, toolCallId: string): string {
  return runId && runId.trim() ? `${runId}:${toolCallId}` : toolCallId;
}

export function registerTrustedPendingExecution(
  pending: Omit<TrustedPendingExecution, "key">,
): void {
  const key = buildPendingKey(
    pending.request.context.runId,
    pending.request.context.toolCallId ?? "",
  );
  pendingExecutions.set(key, { ...pending, key });
}

export function consumeTrustedPendingExecution(params: {
  runId?: string;
  toolCallId: string;
}): TrustedPendingExecution | undefined {
  const key = buildPendingKey(params.runId, params.toolCallId);
  const pending = pendingExecutions.get(key);
  if (!pending) {
    return undefined;
  }
  pendingExecutions.delete(key);
  return pending;
}

export function digestToolResult(params: { isError: boolean; result: unknown }): string {
  return digestTrustedValue({
    status: params.isError ? "error" : "ok",
    result: params.result,
  });
}
