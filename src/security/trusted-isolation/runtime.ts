import crypto from "node:crypto";
import { callGatewayTool } from "../../agents/tools/gateway.js";
import { loadConfig } from "../../config/config.js";
import { resolveExecApprovalSessionTarget } from "../../infra/exec-approval-session-target.js";
import { createSubsystemLogger } from "../../logging/subsystem.js";
import { sendTrustedAuthorize, sendTrustedCompletion, sendTrustedConfirm } from "./client.js";
import { resolveTrustedIsolationConfig } from "./config.js";
import {
  createTrustedAuthorizationInvalidResponseError,
  createTrustedAuthorizationMissingScopeTokenError,
  createTrustedAuthorizationRejectedError,
  createTrustedBackendUnavailableError,
  createTrustedConfirmationInvalidResponseError,
  createTrustedConfirmationRejectedError,
  createTrustedIsolatedExecutionUnavailableError,
  isTrustedIsolationError,
  toTrustedIsolationError,
  type TrustedIsolationErrorCode,
} from "./errors.js";
import { appendTrustedEvidenceRecord, logTrustedEvidenceFailure } from "./evidence.js";
import {
  buildTrustedCompleteRequest,
  buildTrustedIsolationOperation,
  buildTrustedOperationRequest,
  buildTrustedScopeEnvelope,
  resolveTrustedSid,
} from "./request.js";
import { applyTrustedScopeToParams, extractTrustedScopeEnvelope } from "./scope.js";
import {
  consumeTrustedPendingExecution,
  digestToolResult,
  registerTrustedPendingExecution,
} from "./state.js";
import type {
  TrustedAuthorizeResponse,
  TrustedConfirmResponse,
  TrustedConfirmationStatus,
  TrustedEvidenceEvent,
  TrustedEvidenceRecord,
  TrustedIsolationDecision,
  TrustedIsolationExecutionMode,
  TrustedIsolationOperation,
  TrustedIsolationRiskLevel,
  TrustedOperationRequest,
  TrustedPendingExecution,
} from "./types.js";

const log = createSubsystemLogger("security/trusted-isolation");
const sequenceBySession = new Map<string, number>();
const TRUSTED_CONFIRM_PATH = "/v1/trusted/confirm";
const TRUSTED_CONFIRMATION_APPROVAL_TIMEOUT_MS = 30 * 60 * 1000;

type TrustedConfirmationRoute = {
  channel: string;
  to: string;
  accountId?: string;
  threadId?: string | number;
};

function nextSequence(sid: string): number {
  const current = sequenceBySession.get(sid) ?? 0;
  const next = current + 1;
  sequenceBySession.set(sid, next);
  return next;
}

function requiresTrustedAuthorize(params: {
  cfg: ReturnType<typeof resolveTrustedIsolationConfig>;
  operation: TrustedIsolationOperation;
}): boolean {
  return (
    params.cfg.forceTrustedTools.includes(params.operation.toolName) ||
    params.cfg.forceTrustedActions.includes(params.operation.action)
  );
}

function isDecision(value: unknown): value is TrustedIsolationDecision {
  return ["dree", "dia", "die", "duc", "ddeny"].includes(String(value));
}

function isLevel(value: unknown): value is TrustedIsolationRiskLevel {
  return ["L0", "L1", "L2", "L3"].includes(String(value));
}

function isExecutionMode(value: unknown): value is TrustedIsolationExecutionMode {
  return ["ree-direct", "ree-constrained", "isolated"].includes(String(value));
}

function isConfirmationStatus(value: unknown): value is TrustedConfirmationStatus {
  return ["pending", "approved", "denied", "expired"].includes(String(value));
}

function inferLegacyExecutionModeFromDecision(
  decision: TrustedIsolationDecision | undefined,
): TrustedIsolationExecutionMode | undefined {
  if (decision === "dree") {
    return "ree-direct";
  }
  if (decision === "dia") {
    return "ree-constrained";
  }
  if (decision === "die") {
    return "isolated";
  }
  return undefined;
}

function resolveAuthorizeExecutionMode(
  response: Partial<TrustedAuthorizeResponse>,
): TrustedIsolationExecutionMode | undefined {
  if (isExecutionMode(response.executionMode)) {
    return response.executionMode;
  }
  const inferred = inferLegacyExecutionModeFromDecision(response.decision);
  if (inferred) {
    log.warn(
      `trusted authorize response missing executionMode; inferred ${inferred} from decision ${response.decision}`,
    );
  }
  return inferred;
}

function validateTrustedAuthorizeResponse(params: {
  request: TrustedOperationRequest;
  response: unknown;
  requireScopeToken: boolean;
}): TrustedAuthorizeResponse {
  if (!params.response || typeof params.response !== "object") {
    throw createTrustedAuthorizationInvalidResponseError();
  }
  const response = params.response as Partial<TrustedAuthorizeResponse>;
  const executionMode = resolveAuthorizeExecutionMode(response);
  if (typeof response.allow !== "boolean") {
    throw createTrustedAuthorizationInvalidResponseError(new Error("missing allow"));
  }
  if (!isDecision(response.decision) || !isLevel(response.level) || !executionMode) {
    throw createTrustedAuthorizationInvalidResponseError(
      new Error("missing decision or execution metadata"),
    );
  }
  if (typeof response.reason !== "string" || !response.reason.trim()) {
    throw createTrustedAuthorizationInvalidResponseError(new Error("missing reason"));
  }
  if (typeof response.matchedRuleId !== "string" || !response.matchedRuleId.trim()) {
    throw createTrustedAuthorizationInvalidResponseError(new Error("missing matchedRuleId"));
  }
  if (!response.normalizedRequest || typeof response.normalizedRequest !== "object") {
    throw createTrustedAuthorizationInvalidResponseError(new Error("missing normalizedRequest"));
  }
  const normalizedRequest = response.normalizedRequest as TrustedOperationRequest;
  if (
    normalizedRequest.reqId !== params.request.reqId ||
    normalizedRequest.sid !== params.request.sid ||
    normalizedRequest.toolName !== params.request.toolName ||
    normalizedRequest.action !== params.request.action ||
    normalizedRequest.object !== params.request.object ||
    normalizedRequest.normalizedScopeDigest !== params.request.normalizedScopeDigest
  ) {
    throw createTrustedAuthorizationInvalidResponseError(new Error("normalized request mismatch"));
  }
  if (
    response.allow &&
    params.requireScopeToken &&
    executionMode !== "ree-direct" &&
    (typeof response.scopeToken !== "string" || !response.scopeToken.trim())
  ) {
    throw createTrustedAuthorizationMissingScopeTokenError();
  }
  if (!response.classification || typeof response.classification !== "object") {
    throw createTrustedAuthorizationInvalidResponseError(new Error("missing classification"));
  }
  if (response.decision === "duc") {
    const confirmation = response.confirmation;
    if (!confirmation || typeof confirmation !== "object") {
      throw createTrustedAuthorizationInvalidResponseError(new Error("missing confirmation"));
    }
    if (
      typeof confirmation.confirmationRequestId !== "string" ||
      !confirmation.confirmationRequestId.trim() ||
      typeof confirmation.challengeToken !== "string" ||
      !confirmation.challengeToken.trim() ||
      typeof confirmation.prompt !== "string" ||
      !confirmation.prompt.trim() ||
      typeof confirmation.summary !== "string" ||
      !confirmation.summary.trim() ||
      typeof confirmation.expiresAtMs !== "number" ||
      !isExecutionMode(confirmation.executionMode)
    ) {
      throw createTrustedAuthorizationInvalidResponseError(
        new Error("invalid confirmation requirement"),
      );
    }
  }
  return {
    allow: response.allow,
    decision: response.decision,
    level: response.level,
    executionMode,
    reason: response.reason.trim(),
    matchedRuleId: response.matchedRuleId.trim(),
    normalizedRequest,
    classification: response.classification,
    constraints:
      response.constraints && typeof response.constraints === "object"
        ? (response.constraints as Record<string, unknown>)
        : undefined,
    scopeToken: typeof response.scopeToken === "string" ? response.scopeToken.trim() : undefined,
    confirmation:
      response.confirmation && typeof response.confirmation === "object"
        ? {
            confirmationRequestId: String(response.confirmation.confirmationRequestId).trim(),
            challengeToken: String(response.confirmation.challengeToken).trim(),
            prompt: String(response.confirmation.prompt).trim(),
            summary: String(response.confirmation.summary).trim(),
            expiresAtMs: Number(response.confirmation.expiresAtMs),
            executionMode: response.confirmation.executionMode,
          }
        : undefined,
    evidence:
      response.evidence && typeof response.evidence === "object"
        ? (response.evidence as Record<string, unknown>)
        : undefined,
  };
}

function validateTrustedConfirmResponse(params: {
  request: TrustedOperationRequest;
  response: unknown;
  requireScopeToken: boolean;
}): TrustedConfirmResponse {
  if (!params.response || typeof params.response !== "object") {
    throw createTrustedConfirmationInvalidResponseError();
  }
  const response = params.response as Partial<TrustedConfirmResponse>;
  if (
    typeof response.ok !== "boolean" ||
    typeof response.confirmationRequestId !== "string" ||
    !response.confirmationRequestId.trim() ||
    !isConfirmationStatus(response.status) ||
    !isDecision(response.decision) ||
    !isLevel(response.level) ||
    !isExecutionMode(response.executionMode) ||
    typeof response.reason !== "string" ||
    !response.reason.trim() ||
    typeof response.matchedRuleId !== "string" ||
    !response.matchedRuleId.trim() ||
    typeof response.confirmedAtMs !== "number" ||
    typeof response.operatorId !== "string" ||
    !response.operatorId.trim()
  ) {
    throw createTrustedConfirmationInvalidResponseError(new Error("missing confirmation metadata"));
  }
  if (!response.normalizedRequest || typeof response.normalizedRequest !== "object") {
    throw createTrustedConfirmationInvalidResponseError(new Error("missing normalizedRequest"));
  }
  const normalizedRequest = response.normalizedRequest as TrustedOperationRequest;
  if (
    normalizedRequest.reqId !== params.request.reqId ||
    normalizedRequest.sid !== params.request.sid ||
    normalizedRequest.toolName !== params.request.toolName ||
    normalizedRequest.action !== params.request.action ||
    normalizedRequest.object !== params.request.object ||
    normalizedRequest.normalizedScopeDigest !== params.request.normalizedScopeDigest
  ) {
    throw createTrustedConfirmationInvalidResponseError(new Error("normalized request mismatch"));
  }
  if (
    response.ok &&
    params.requireScopeToken &&
    response.executionMode !== "ree-direct" &&
    (typeof response.scopeToken !== "string" || !response.scopeToken.trim())
  ) {
    throw createTrustedAuthorizationMissingScopeTokenError();
  }
  return {
    ok: response.ok,
    confirmationRequestId: response.confirmationRequestId.trim(),
    status: response.status,
    decision: response.decision,
    level: response.level,
    executionMode: response.executionMode,
    reason: response.reason.trim(),
    matchedRuleId: response.matchedRuleId.trim(),
    normalizedRequest,
    confirmedAtMs: response.confirmedAtMs,
    operatorId: response.operatorId.trim(),
    scopeToken: typeof response.scopeToken === "string" ? response.scopeToken.trim() : undefined,
    evidence:
      response.evidence && typeof response.evidence === "object"
        ? (response.evidence as Record<string, unknown>)
        : undefined,
  };
}

function resolveTrustedConfirmationRoute(params: {
  request: TrustedOperationRequest;
  approvalId: string;
}): TrustedConfirmationRoute | undefined {
  const sessionKey = params.request.context.sessionKey?.trim();
  if (!sessionKey) {
    return undefined;
  }
  const target = resolveExecApprovalSessionTarget({
    cfg: loadConfig(),
    request: {
      id: params.approvalId,
      request: {
        command: params.request.scope.exec?.rawCommand ?? params.request.object,
        agentId: params.request.context.agentId ?? null,
        sessionKey,
      },
      createdAtMs: 0,
      expiresAtMs: 0,
    },
  });
  if (!target?.channel || !target.to) {
    return undefined;
  }
  return {
    channel: target.channel,
    to: target.to,
    accountId: target.accountId,
    threadId: target.threadId,
  };
}

async function requestTrustedConfirmationApproval(params: {
  request: TrustedOperationRequest;
  confirmationRequestId: string;
}): Promise<{ decision: string | null; resolvedBy?: string }> {
  const approvalId = `trusted:${params.confirmationRequestId}`;
  const route = resolveTrustedConfirmationRoute({
    request: params.request,
    approvalId,
  });
  const registration = await callGatewayTool<{
    id?: string;
    decision?: string | null;
  }>(
    "exec.approval.request",
    { timeoutMs: TRUSTED_CONFIRMATION_APPROVAL_TIMEOUT_MS + 10_000 },
    {
      id: approvalId,
      command: params.request.scope.exec?.rawCommand ?? params.request.object,
      cwd:
        params.request.context.workdir ??
        params.request.scope.exec?.cwd ??
        params.request.context.workspaceRoot,
      host: "gateway",
      security: "full",
      ask: "always",
      agentId: params.request.context.agentId,
      sessionKey: params.request.context.sessionKey,
      turnSourceChannel: route?.channel,
      turnSourceTo: route?.to,
      turnSourceAccountId: route?.accountId,
      turnSourceThreadId: route?.threadId,
      timeoutMs: TRUSTED_CONFIRMATION_APPROVAL_TIMEOUT_MS,
      twoPhase: true,
    },
    { expectFinal: false },
  );

  if (Object.hasOwn(registration ?? {}, "decision")) {
    return {
      decision: typeof registration?.decision === "string" ? registration.decision : null,
    };
  }

  const resolution = await callGatewayTool<{
    decision?: string | null;
    resolvedBy?: string | null;
  }>(
    "exec.approval.waitDecision",
    { timeoutMs: TRUSTED_CONFIRMATION_APPROVAL_TIMEOUT_MS + 10_000 },
    { id: String(registration?.id || approvalId) },
  );

  return {
    decision: typeof resolution?.decision === "string" ? resolution.decision : null,
    resolvedBy:
      typeof resolution?.resolvedBy === "string" ? resolution.resolvedBy.trim() : undefined,
  };
}

function buildConfirmedAuthorizeResponse(params: {
  authorizeResponse: TrustedAuthorizeResponse;
  confirmResponse: TrustedConfirmResponse;
}): TrustedAuthorizeResponse {
  return {
    ...params.authorizeResponse,
    allow: params.confirmResponse.ok,
    decision: params.confirmResponse.decision,
    level: params.confirmResponse.level,
    executionMode: params.confirmResponse.executionMode,
    reason: params.confirmResponse.reason,
    matchedRuleId: params.confirmResponse.matchedRuleId,
    normalizedRequest: params.confirmResponse.normalizedRequest,
    scopeToken: params.confirmResponse.scopeToken,
    evidence: {
      ...params.authorizeResponse.evidence,
      ...params.confirmResponse.evidence,
    },
  };
}

function buildEvidenceBase(params: {
  event: TrustedEvidenceEvent;
  request: TrustedOperationRequest;
  level: TrustedIsolationRiskLevel;
  decision: TrustedIsolationDecision;
  executionMode: TrustedIsolationExecutionMode;
  matchedRuleId?: string;
  status: string;
  ts: number;
  evidence?: Record<string, unknown>;
  errorCode?: string;
  errorMessage?: string;
  confirmationRequestId?: string;
  confirmationStatus?: TrustedConfirmationStatus;
  confirmedBy?: string;
  backendStage?: "authorize" | "complete";
  durationMs?: number;
  resultDigest?: string;
}): Omit<TrustedEvidenceRecord, "entryHash" | "prevHash"> {
  return {
    event: params.event,
    ts: params.ts,
    reqId: params.request.reqId,
    sid: params.request.sid,
    toolName: params.request.toolName,
    action: params.request.action,
    object: params.request.object,
    level: params.level,
    decision: params.decision,
    executionMode: params.executionMode,
    matchedRuleId: params.matchedRuleId,
    normalizedScopeDigest: params.request.normalizedScopeDigest,
    requestDigest: params.request.requestDigest,
    status: params.status,
    durationMs: params.durationMs,
    resultDigest: params.resultDigest,
    errorCode: params.errorCode,
    errorMessage: params.errorMessage,
    backendStage: params.backendStage,
    confirmationRequestId: params.confirmationRequestId,
    confirmationStatus: params.confirmationStatus,
    confirmedBy: params.confirmedBy,
    context: params.request.context,
    evidence: params.evidence,
  };
}

async function appendTrustedEvidenceSafely(params: {
  cfg: ReturnType<typeof resolveTrustedIsolationConfig>;
  record: Omit<TrustedEvidenceRecord, "entryHash" | "prevHash">;
}): Promise<void> {
  try {
    await appendTrustedEvidenceRecord({
      filePath: params.cfg.evidenceFile,
      record: params.record,
    });
  } catch (error) {
    logTrustedEvidenceFailure(error);
  }
}

function normalizeTrustedErrorCode(error: unknown): TrustedIsolationErrorCode | undefined {
  const trusted = toTrustedIsolationError(error);
  if (trusted) {
    return trusted.code;
  }
  if (error && typeof error === "object") {
    const code = (error as { code?: unknown; errorCode?: unknown }).code;
    if (typeof code === "string") {
      return code as TrustedIsolationErrorCode;
    }
    const errorCode = (error as { errorCode?: unknown }).errorCode;
    if (typeof errorCode === "string") {
      return errorCode as TrustedIsolationErrorCode;
    }
  }
  return undefined;
}

function extractErrorInfo(result: unknown): {
  errorCode?: TrustedIsolationErrorCode;
  errorMessage?: string;
} {
  if (result instanceof Error) {
    return {
      errorCode: normalizeTrustedErrorCode(result),
      errorMessage: result.message,
    };
  }
  if (result && typeof result === "object") {
    const record = result as Record<string, unknown>;
    return {
      errorCode: normalizeTrustedErrorCode(record),
      errorMessage:
        typeof record.error === "string"
          ? record.error
          : typeof record.message === "string"
            ? record.message
            : undefined,
    };
  }
  return {
    errorMessage: typeof result === "string" ? result : undefined,
  };
}

function classifyFinalizeEvent(params: { isError: boolean; result: unknown }): {
  event: "complete" | "violation";
  status: "ok" | "error" | "violation";
  errorCode?: TrustedIsolationErrorCode;
  errorMessage?: string;
} {
  if (!params.isError) {
    return { event: "complete", status: "ok" };
  }
  const { errorCode, errorMessage } = extractErrorInfo(params.result);
  if (
    errorCode === "trusted_scope_token_expired" ||
    errorCode === "trusted_scope_token_verification_failed" ||
    errorCode === "trusted_scope_violation"
  ) {
    return {
      event: "violation",
      status: "violation",
      errorCode,
      errorMessage,
    };
  }
  return {
    event: "complete",
    status: "error",
    errorCode,
    errorMessage,
  };
}

async function finalizeTrustedPendingExecution(params: {
  cfg: ReturnType<typeof resolveTrustedIsolationConfig>;
  pending: TrustedPendingExecution;
  finishedAtMs?: number;
  isError: boolean;
  result: unknown;
}): Promise<void> {
  const finishedAtMs = params.finishedAtMs ?? Date.now();
  const resultDigest = digestToolResult({
    isError: params.isError,
    result: params.result,
  });
  const classified = classifyFinalizeEvent({
    isError: params.isError,
    result: params.result,
  });
  const completionRequest = buildTrustedCompleteRequest({
    pending: params.pending,
    finishedAtMs,
    status: classified.status,
    resultDigest,
    errorCode: classified.errorCode,
    errorMessage: classified.errorMessage,
  });

  if (params.pending.backendBaseUrl) {
    try {
      await sendTrustedCompletion({
        backendBaseUrl: params.pending.backendBaseUrl,
        completePath: params.cfg.completePath,
        timeoutMs: params.cfg.requestTimeoutMs,
        request: completionRequest,
      });
    } catch (error) {
      const trustedError =
        toTrustedIsolationError(error) ?? createTrustedBackendUnavailableError(error);
      await appendTrustedEvidenceSafely({
        cfg: params.cfg,
        record: buildEvidenceBase({
          event: "backend_error",
          request: params.pending.request,
          level: params.pending.response.level,
          decision: params.pending.response.decision,
          executionMode: params.pending.response.executionMode,
          matchedRuleId: params.pending.response.matchedRuleId,
          status: trustedError.code,
          ts: finishedAtMs,
          errorCode: trustedError.code,
          errorMessage: trustedError.message,
          confirmationRequestId: params.pending.confirmationRequestId,
          confirmationStatus: params.pending.confirmationStatus,
          confirmedBy: params.pending.confirmedBy,
          backendStage: "complete",
        }),
      });
    }
  }

  await appendTrustedEvidenceSafely({
    cfg: params.cfg,
    record: buildEvidenceBase({
      event: classified.event,
      request: params.pending.request,
      level: params.pending.response.level,
      decision: params.pending.response.decision,
      executionMode: params.pending.response.executionMode,
      matchedRuleId: params.pending.response.matchedRuleId,
      status: classified.errorCode ?? classified.status,
      ts: finishedAtMs,
      durationMs: completionRequest.durationMs,
      resultDigest,
      errorCode: classified.errorCode,
      errorMessage: classified.errorMessage,
      confirmationRequestId: params.pending.confirmationRequestId,
      confirmationStatus: params.pending.confirmationStatus,
      confirmedBy: params.pending.confirmedBy,
      evidence: params.pending.response.evidence,
    }),
  });
}

export async function enforceTrustedIsolationBeforeToolCall(params: {
  toolName: string;
  inputParams: unknown;
  context?: {
    agentId?: string;
    sessionKey?: string;
    sessionId?: string;
    runId?: string;
  };
  toolCallId?: string;
}): Promise<
  { blocked: true; reason: string } | { blocked: false; params: Record<string, unknown> }
> {
  const cfg = resolveTrustedIsolationConfig(params.context?.agentId);
  const operation = buildTrustedIsolationOperation({
    toolName: params.toolName,
    inputParams: params.inputParams,
    context: params.context,
    toolCallId: params.toolCallId,
  });
  const initialRequest = buildTrustedOperationRequest({
    operation,
    sequence: nextSequence(
      resolveTrustedSid({
        agentId: operation.agentId,
        runId: operation.runId,
        toolCallId: operation.toolCallId,
        sessionId: operation.sessionId,
        sessionKey: operation.sessionKey,
      }),
    ),
    ttlMs: cfg.ttlMs,
    reqId: crypto.randomUUID(),
  });

  if (!cfg.enabled || !requiresTrustedAuthorize({ cfg, operation })) {
    return {
      blocked: false,
      params:
        params.inputParams && typeof params.inputParams === "object"
          ? (params.inputParams as Record<string, unknown>)
          : {},
    };
  }

  if (!cfg.backendBaseUrl?.trim()) {
    const error = createTrustedBackendUnavailableError();
    await appendTrustedEvidenceSafely({
      cfg,
      record: buildEvidenceBase({
        event: "backend_error",
        request: initialRequest,
        level: initialRequest.level,
        decision: "ddeny",
        executionMode: "ree-constrained",
        status: error.code,
        ts: Date.now(),
        errorCode: error.code,
        errorMessage: error.message,
        backendStage: "authorize",
      }),
    });
    return { blocked: true, reason: error.message };
  }

  let response: TrustedAuthorizeResponse;
  try {
    response = validateTrustedAuthorizeResponse({
      request: initialRequest,
      response: await sendTrustedAuthorize({
        backendBaseUrl: cfg.backendBaseUrl,
        authorizePath: cfg.authorizePath,
        timeoutMs: cfg.requestTimeoutMs,
        request: initialRequest,
      }),
      requireScopeToken: cfg.requireScopeToken,
    });
  } catch (error) {
    const trustedError = isTrustedIsolationError(error)
      ? error
      : createTrustedAuthorizationInvalidResponseError(error);
    await appendTrustedEvidenceSafely({
      cfg,
      record: buildEvidenceBase({
        event: "backend_error",
        request: initialRequest,
        level: initialRequest.level,
        decision: "ddeny",
        executionMode: "ree-constrained",
        status: trustedError.code,
        ts: Date.now(),
        errorCode: trustedError.code,
        errorMessage: trustedError.message,
        backendStage: "authorize",
      }),
    });
    return { blocked: true, reason: trustedError.message };
  }

  const authoritativeRequest = response.normalizedRequest;
  const confirmationRequestId = response.confirmation?.confirmationRequestId;
  let confirmationStatus: TrustedConfirmationStatus | undefined;
  let confirmedBy: string | undefined;

  const authorizeEvidence = {
    ...response.evidence,
    classification: response.classification,
    normalizedRequest: authoritativeRequest,
    confirmation: response.confirmation,
  };

  if (response.decision === "ddeny") {
    const rejectionError = createTrustedAuthorizationRejectedError(response.reason);
    await appendTrustedEvidenceSafely({
      cfg,
      record: buildEvidenceBase({
        event: "deny",
        request: authoritativeRequest,
        level: response.level,
        decision: response.decision,
        executionMode: response.executionMode,
        matchedRuleId: response.matchedRuleId,
        status: rejectionError.code,
        ts: Date.now(),
        evidence: response.evidence,
        errorCode: rejectionError.code,
        errorMessage: response.reason,
      }),
    });
    return { blocked: true, reason: response.reason };
  }

  await appendTrustedEvidenceSafely({
    cfg,
    record: buildEvidenceBase({
      event: "authorize",
      request: authoritativeRequest,
      level: response.level,
      decision: response.decision,
      executionMode: response.executionMode,
      matchedRuleId: response.matchedRuleId,
      status: "authorized",
      ts: Date.now(),
      confirmationRequestId,
      confirmationStatus: response.decision === "duc" ? "pending" : undefined,
      evidence: authorizeEvidence,
    }),
  });

  let effectiveResponse = response;
  if (response.decision === "duc") {
    const confirmation = response.confirmation;
    if (!confirmation) {
      const error = createTrustedConfirmationInvalidResponseError(
        new Error("missing confirmation requirement"),
      );
      await appendTrustedEvidenceSafely({
        cfg,
        record: buildEvidenceBase({
          event: "backend_error",
          request: authoritativeRequest,
          level: response.level,
          decision: response.decision,
          executionMode: response.executionMode,
          matchedRuleId: response.matchedRuleId,
          status: error.code,
          ts: Date.now(),
          errorCode: error.code,
          errorMessage: error.message,
          confirmationRequestId,
          confirmationStatus: "pending",
          evidence: authorizeEvidence,
        }),
      });
      return { blocked: true, reason: error.message };
    }
    let approvalDecision: { decision: string | null; resolvedBy?: string } | undefined;
    try {
      approvalDecision = await requestTrustedConfirmationApproval({
        request: authoritativeRequest,
        confirmationRequestId: confirmation?.confirmationRequestId ?? authoritativeRequest.reqId,
      });
    } catch (error) {
      log.warn(`trusted confirmation approval request failed: ${String(error)}`);
    }

    if (
      !approvalDecision?.decision ||
      !["allow-once", "allow-always", "deny"].includes(approvalDecision.decision)
    ) {
      await appendTrustedEvidenceSafely({
        cfg,
        record: buildEvidenceBase({
          event: "deny",
          request: authoritativeRequest,
          level: response.level,
          decision: response.decision,
          executionMode: response.executionMode,
          matchedRuleId: response.matchedRuleId,
          status: "confirmation_required",
          ts: Date.now(),
          confirmationRequestId,
          confirmationStatus: "pending",
          evidence: authorizeEvidence,
          errorMessage: response.reason,
        }),
      });
      return {
        blocked: true,
        reason:
          `${response.reason} ` +
          `(reply with allow-once|allow-always|deny; if needed, use /approve ` +
          `trusted:${confirmationRequestId ?? authoritativeRequest.reqId} ` +
          `allow-once|allow-always|deny)`,
      };
    }

    let confirmResponse: TrustedConfirmResponse;
    try {
      confirmResponse = validateTrustedConfirmResponse({
        request: authoritativeRequest,
        response: await sendTrustedConfirm({
          backendBaseUrl: cfg.backendBaseUrl,
          confirmPath: TRUSTED_CONFIRM_PATH,
          timeoutMs: cfg.requestTimeoutMs,
          request: {
            confirmationRequestId: confirmation.confirmationRequestId,
            challengeToken: confirmation.challengeToken,
            operatorId:
              approvalDecision.resolvedBy ?? `approval:${confirmation.confirmationRequestId}`,
            decision: approvalDecision.decision === "deny" ? "deny" : "approve",
            reason:
              approvalDecision.decision === "deny"
                ? "operator denied trusted confirmation"
                : "operator approved trusted confirmation",
            context: {
              approvalDecision: approvalDecision.decision,
            },
          },
        }),
        requireScopeToken: cfg.requireScopeToken,
      });
    } catch (error) {
      const trustedError = isTrustedIsolationError(error)
        ? error
        : createTrustedConfirmationInvalidResponseError(error);
      await appendTrustedEvidenceSafely({
        cfg,
        record: buildEvidenceBase({
          event: "backend_error",
          request: authoritativeRequest,
          level: response.level,
          decision: response.decision,
          executionMode: response.executionMode,
          matchedRuleId: response.matchedRuleId,
          status: trustedError.code,
          ts: Date.now(),
          errorCode: trustedError.code,
          errorMessage: trustedError.message,
          confirmationRequestId,
          confirmationStatus: "pending",
          evidence: authorizeEvidence,
        }),
      });
      return { blocked: true, reason: trustedError.message };
    }

    confirmationStatus = confirmResponse.status;
    confirmedBy = confirmResponse.operatorId;
    await appendTrustedEvidenceSafely({
      cfg,
      record: buildEvidenceBase({
        event: "confirm",
        request: authoritativeRequest,
        level: confirmResponse.level,
        decision: confirmResponse.decision,
        executionMode: confirmResponse.executionMode,
        matchedRuleId: confirmResponse.matchedRuleId,
        status: confirmResponse.status,
        ts: confirmResponse.confirmedAtMs,
        confirmationRequestId: confirmResponse.confirmationRequestId,
        confirmationStatus: confirmResponse.status,
        confirmedBy: confirmResponse.operatorId,
        evidence: {
          ...authorizeEvidence,
          ...confirmResponse.evidence,
        },
      }),
    });

    if (!confirmResponse.ok || confirmResponse.status !== "approved") {
      const rejectionError = createTrustedConfirmationRejectedError(confirmResponse.reason);
      return { blocked: true, reason: rejectionError.message };
    }

    effectiveResponse = buildConfirmedAuthorizeResponse({
      authorizeResponse: response,
      confirmResponse,
    });
  }

  if (!effectiveResponse.allow) {
    const rejectionError = createTrustedAuthorizationRejectedError(effectiveResponse.reason);
    await appendTrustedEvidenceSafely({
      cfg,
      record: buildEvidenceBase({
        event: "deny",
        request: authoritativeRequest,
        level: effectiveResponse.level,
        decision: effectiveResponse.decision,
        executionMode: effectiveResponse.executionMode,
        matchedRuleId: effectiveResponse.matchedRuleId,
        status: rejectionError.code,
        ts: Date.now(),
        confirmationRequestId,
        confirmationStatus,
        confirmedBy,
        evidence: effectiveResponse.evidence,
        errorCode: rejectionError.code,
        errorMessage: effectiveResponse.reason,
      }),
    });
    return { blocked: true, reason: effectiveResponse.reason };
  }

  const scopeToken = effectiveResponse.scopeToken;
  if (cfg.requireScopeToken && effectiveResponse.executionMode !== "ree-direct" && !scopeToken) {
    const error = createTrustedAuthorizationMissingScopeTokenError();
    await appendTrustedEvidenceSafely({
      cfg,
      record: buildEvidenceBase({
        event: "backend_error",
        request: authoritativeRequest,
        level: effectiveResponse.level,
        decision: "ddeny",
        executionMode: effectiveResponse.executionMode,
        matchedRuleId: effectiveResponse.matchedRuleId,
        status: error.code,
        ts: Date.now(),
        confirmationRequestId,
        confirmationStatus,
        confirmedBy,
        evidence: effectiveResponse.evidence,
        errorCode: error.code,
        errorMessage: error.message,
        backendStage: "authorize",
      }),
    });
    return { blocked: true, reason: error.message };
  }

  const adjustedParams =
    effectiveResponse.executionMode === "ree-constrained"
      ? applyTrustedScopeToParams({
          inputParams: params.inputParams,
          envelope: buildTrustedScopeEnvelope({
            request: authoritativeRequest,
            scopeToken: scopeToken ?? "",
            level: effectiveResponse.level,
            constraints: effectiveResponse.constraints,
          }),
        })
      : params.inputParams && typeof params.inputParams === "object"
        ? (params.inputParams as Record<string, unknown>)
        : {};

  const pendingExecution = {
    key: "pending",
    request: authoritativeRequest,
    response: effectiveResponse,
    scopeToken,
    startedAtMs: Date.now(),
    backendBaseUrl: cfg.backendBaseUrl,
    confirmationRequestId,
    confirmationStatus,
    confirmedBy,
  } satisfies TrustedPendingExecution;

  if (effectiveResponse.executionMode === "isolated") {
    const error = createTrustedIsolatedExecutionUnavailableError();
    await finalizeTrustedPendingExecution({
      cfg,
      pending: pendingExecution,
      isError: true,
      result: error,
    });
    return { blocked: true, reason: error.message };
  }

  if (params.toolCallId) {
    registerTrustedPendingExecution({
      request: authoritativeRequest,
      response: effectiveResponse,
      scopeToken,
      startedAtMs: pendingExecution.startedAtMs,
      backendBaseUrl: cfg.backendBaseUrl,
      confirmationRequestId,
      confirmationStatus,
      confirmedBy,
    });
  }

  return { blocked: false, params: adjustedParams };
}

export async function finalizeTrustedIsolationToolCall(params: {
  toolName: string;
  toolCallId: string;
  runId?: string;
  isError: boolean;
  result: unknown;
}): Promise<void> {
  const pending = consumeTrustedPendingExecution({
    runId: params.runId,
    toolCallId: params.toolCallId,
  });
  if (!pending) {
    return;
  }

  const cfg = resolveTrustedIsolationConfig(pending.request.context.agentId);
  await finalizeTrustedPendingExecution({
    cfg,
    pending,
    isError: params.isError,
    result: params.result,
  });
}

export function hasTrustedScopeEnvelope(params: unknown): boolean {
  return Boolean(extractTrustedScopeEnvelope(params));
}
