import { resolveAgentWorkspaceDir } from "../../agents/agent-scope.js";
import { loadConfig } from "../../config/config.js";
import { splitShellArgs } from "../../utils/shell-argv.js";
import { digestTrustedValue } from "./digest.js";
import type {
  TrustedCompleteRequest,
  TrustedIsolationAction,
  TrustedIsolationContext,
  TrustedIsolationOperation,
  TrustedIsolationRiskLevel,
  TrustedIsolationScope,
  TrustedOperationRequest,
  TrustedPendingExecution,
  TrustedScopeEnvelope,
  TrustedScopeTokenPayload,
} from "./types.js";

function toRecord(params: unknown): Record<string, unknown> {
  return params && typeof params === "object" ? (params as Record<string, unknown>) : {};
}

function normalizeOptionalText(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function normalizeEnvSubset(input: unknown): Record<string, string> | undefined {
  if (!input || typeof input !== "object") {
    return undefined;
  }
  const entries = Object.entries(input as Record<string, unknown>)
    .filter(([, value]) => typeof value === "string")
    .toSorted(([left], [right]) => left.localeCompare(right));
  if (entries.length === 0) {
    return undefined;
  }
  return Object.fromEntries(entries) as Record<string, string>;
}

const SHELL_COMPOUND_HEAD_KEYWORDS = new Set([
  "(",
  ":",
  "case",
  "for",
  "function",
  "if",
  "select",
  "time",
  "until",
  "while",
  "{",
]);

function isShellCompoundCommand(rawCommand: string): boolean {
  const trimmed = normalizeOptionalText(rawCommand);
  if (!trimmed) {
    return false;
  }
  const parsed = splitShellArgs(trimmed);
  const head = (parsed?.[0] ?? "")
    .replace(/^[({]+/, "")
    .replace(/[;)}]+$/, "")
    .trim()
    .toLowerCase();
  if (head && SHELL_COMPOUND_HEAD_KEYWORDS.has(head)) {
    return true;
  }

  let inSingle = false;
  let inDouble = false;
  let escaped = false;
  for (let index = 0; index < trimmed.length; index += 1) {
    const ch = trimmed[index];
    const next = trimmed[index + 1];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (!inSingle && ch === "\\") {
      escaped = true;
      continue;
    }
    if (!inDouble && ch === "'") {
      inSingle = !inSingle;
      continue;
    }
    if (!inSingle && ch === '"') {
      inDouble = !inDouble;
      continue;
    }
    if (inSingle || inDouble) {
      continue;
    }
    if (ch === ";" || ch === "|" || ch === "\n" || ch === "\r") {
      return true;
    }
    if ((ch === "&" || ch === "|") && next === ch) {
      return true;
    }
  }
  return false;
}

export function resolveTrustedAction(
  toolName: string,
  params: Record<string, unknown>,
): TrustedIsolationAction {
  const normalized = toolName.trim().toLowerCase();
  if (normalized === "exec" || normalized === "bash" || normalized.includes("command")) {
    return "exec";
  }
  if (normalized === "read" || normalized.includes("list") || normalized.includes("view")) {
    return "read";
  }
  if (normalized === "write" || normalized === "edit" || normalized === "apply_patch") {
    return "modify";
  }
  if (normalized.includes("delete") || normalized.includes("remove") || normalized === "rm") {
    return "delete";
  }
  if (
    normalized.includes("upload") ||
    normalized.includes("export") ||
    normalized.includes("send")
  ) {
    return "export";
  }
  if (typeof params.command === "string") {
    return "exec";
  }
  return "unknown";
}

export function resolveTrustedObject(
  toolName: string,
  action: TrustedIsolationAction,
  params: Record<string, unknown>,
): string {
  if (action === "exec") {
    const command = normalizeOptionalText(params.command);
    if (command) {
      return command;
    }
  }
  for (const key of ["path", "file", "filepath", "target", "destination", "dst"]) {
    const value = normalizeOptionalText(params[key]);
    if (value) {
      return value;
    }
  }
  return `tool:${toolName}`;
}

function resolveTrustedScope(
  action: TrustedIsolationAction,
  object: string,
  params: Record<string, unknown>,
): TrustedIsolationScope {
  if (action === "exec") {
    const rawCommand = normalizeOptionalText(params.command) ?? "";
    const shellCompound = isShellCompoundCommand(rawCommand);
    const parsed = rawCommand && !shellCompound ? splitShellArgs(rawCommand) : null;
    return {
      action,
      target: object,
      exec: {
        matchMode: shellCompound ? "shell-exact" : "exact",
        rawCommand,
        command: shellCompound ? "shell-compound" : (parsed?.[0] ?? rawCommand),
        args: parsed?.slice(1) ?? [],
        cwd: normalizeOptionalText(params.workdir),
        envSubset: normalizeEnvSubset(params.env),
      },
      restrictions: {},
    };
  }

  const scope: TrustedIsolationScope = {
    action,
    target: object,
    restrictions: {},
  };
  const pathValue = normalizeOptionalText(params.path) ?? normalizeOptionalText(params.file);
  if (pathValue && (action === "read" || action === "modify" || action === "delete")) {
    scope.allowedPath = pathValue;
    const slash = pathValue.lastIndexOf("/");
    if (slash > 0) {
      scope.allowedPrefixes = [pathValue.slice(0, slash)];
    }
  }
  return scope;
}

function buildTrustedContext(params: {
  context?: {
    agentId?: string;
    sessionKey?: string;
    sessionId?: string;
    runId?: string;
  };
  toolCallId?: string;
  inputParams: Record<string, unknown>;
}): TrustedIsolationContext {
  const agentId = normalizeOptionalText(params.context?.agentId);
  const requestedWorkdir = normalizeOptionalText(params.inputParams.workdir);
  const workspaceRoot =
    requestedWorkdir ?? (agentId ? resolveAgentWorkspaceDir(loadConfig(), agentId) : undefined);
  return {
    agentId,
    runId: normalizeOptionalText(params.context?.runId),
    toolCallId: normalizeOptionalText(params.toolCallId),
    sessionKey: normalizeOptionalText(params.context?.sessionKey),
    sessionId: normalizeOptionalText(params.context?.sessionId),
    workdir: requestedWorkdir,
    workspaceRoot,
  };
}

export function resolveTrustedSid(context: TrustedIsolationContext): string {
  return context.sessionKey || context.sessionId || "anonymous";
}

export function defaultTrustedLevel(action: TrustedIsolationAction): TrustedIsolationRiskLevel {
  return action === "exec" ? "L1" : "L0";
}

export function buildTrustedIsolationOperation(params: {
  toolName: string;
  inputParams: unknown;
  context?: {
    agentId?: string;
    sessionKey?: string;
    sessionId?: string;
    runId?: string;
  };
  toolCallId?: string;
}): TrustedIsolationOperation {
  const record = toRecord(params.inputParams);
  const action = resolveTrustedAction(params.toolName, record);
  return {
    sessionId: normalizeOptionalText(params.context?.sessionId),
    sessionKey: normalizeOptionalText(params.context?.sessionKey),
    agentId: normalizeOptionalText(params.context?.agentId),
    runId: normalizeOptionalText(params.context?.runId),
    toolCallId: normalizeOptionalText(params.toolCallId),
    toolName: params.toolName,
    action,
    object: resolveTrustedObject(params.toolName, action, record),
    params: record,
  };
}

export function buildTrustedOperationRequest(params: {
  operation: TrustedIsolationOperation;
  sequence: number;
  ttlMs: number;
  reqId: string;
  issuedAtMs?: number;
}): TrustedOperationRequest {
  const context = buildTrustedContext({
    context: {
      agentId: params.operation.agentId,
      sessionKey: params.operation.sessionKey,
      sessionId: params.operation.sessionId,
      runId: params.operation.runId,
    },
    toolCallId: params.operation.toolCallId,
    inputParams: params.operation.params,
  });
  const scope = resolveTrustedScope(
    params.operation.action,
    params.operation.object,
    params.operation.params,
  );
  const normalizedScopeDigest = digestTrustedValue(scope);
  const issuedAtMs = params.issuedAtMs ?? Date.now();
  const baseRequest = {
    version: 1 as const,
    reqId: params.reqId,
    sid: resolveTrustedSid(context),
    seq: params.sequence,
    ttlMs: params.ttlMs,
    issuedAtMs,
    toolName: params.operation.toolName,
    action: params.operation.action,
    object: params.operation.object,
    scope,
    context,
    level: defaultTrustedLevel(params.operation.action),
    normalizedScopeDigest,
  };
  return {
    ...baseRequest,
    requestDigest: digestTrustedValue(baseRequest),
  };
}

export function buildTrustedScopeEnvelope(params: {
  request: TrustedOperationRequest;
  scopeToken: string;
  level: TrustedIsolationRiskLevel;
  constraints?: Record<string, unknown>;
  issuedAtMs?: number;
  expiresAtMs?: number;
}): TrustedScopeEnvelope {
  return {
    reqId: params.request.reqId,
    sid: params.request.sid,
    token: params.scopeToken,
    action: params.request.action,
    object: params.request.object,
    level: params.level,
    normalizedScopeDigest: params.request.normalizedScopeDigest,
    issuedAtMs: params.issuedAtMs ?? params.request.issuedAtMs,
    expiresAtMs: params.expiresAtMs ?? params.request.issuedAtMs + params.request.ttlMs,
    constraints: params.constraints,
  };
}

export function buildTrustedScopeTokenPayload(
  request: TrustedOperationRequest,
): TrustedScopeTokenPayload {
  return {
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
}

export function buildTrustedCompleteRequest(params: {
  pending: TrustedPendingExecution;
  finishedAtMs: number;
  status: "ok" | "error" | "violation";
  resultDigest: string;
  errorCode?: string;
  errorMessage?: string;
}): TrustedCompleteRequest {
  const durationMs = Math.max(0, params.finishedAtMs - params.pending.startedAtMs);
  return {
    reqId: params.pending.request.reqId,
    sid: params.pending.request.sid,
    toolName: params.pending.request.toolName,
    action: params.pending.request.action,
    object: params.pending.request.object,
    level: params.pending.response.level,
    decision: params.pending.response.decision,
    executionMode: params.pending.response.executionMode,
    matchedRuleId: params.pending.response.matchedRuleId,
    normalizedScopeDigest: params.pending.request.normalizedScopeDigest,
    requestDigest: params.pending.request.requestDigest,
    startedAtMs: params.pending.startedAtMs,
    finishedAtMs: params.finishedAtMs,
    durationMs,
    status: params.status,
    resultDigest: params.resultDigest,
    errorCode: params.errorCode,
    errorMessage: params.errorMessage,
    confirmationRequestId: params.pending.confirmationRequestId,
    confirmationStatus: params.pending.confirmationStatus,
    confirmedBy: params.pending.confirmedBy,
    context: params.pending.request.context,
  };
}
