import { loadConfig } from "../../config/config.js";
import { hasApprovalTurnSourceRoute } from "../../infra/approval-turn-source.js";
import { sanitizeExecApprovalDisplayText } from "../../infra/exec-approval-command-display.js";
import type { ExecApprovalForwarder } from "../../infra/exec-approval-forwarder.js";
import { buildExecApprovalPendingReplyPayload } from "../../infra/exec-approval-reply.js";
import {
  DEFAULT_EXEC_APPROVAL_TIMEOUT_MS,
  type ExecApprovalDecision,
  type ExecApprovalRequestPayload,
} from "../../infra/exec-approvals.js";
import {
  deliverOutboundPayloads,
  type DeliverOutboundPayloadsParams,
} from "../../infra/outbound/deliver.js";
import {
  buildSystemRunApprovalBinding,
  buildSystemRunApprovalEnvBinding,
} from "../../infra/system-run-approval-binding.js";
import { resolveSystemRunApprovalRequestContext } from "../../infra/system-run-approval-context.js";
import {
  isDeliverableMessageChannel,
  normalizeMessageChannel,
} from "../../utils/message-channel.js";
import type { ExecApprovalManager } from "../exec-approval-manager.js";
import {
  ErrorCodes,
  errorShape,
  formatValidationErrors,
  validateExecApprovalRequestParams,
  validateExecApprovalResolveParams,
  validateExecApprovalResolveRouteParams,
} from "../protocol/index.js";
import type { GatewayRequestHandlers } from "./types.js";

const APPROVAL_NOT_FOUND_DETAILS = {
  reason: ErrorCodes.APPROVAL_NOT_FOUND,
} as const;

type ExecApprovalRouteParams = {
  sessionKey?: string | null;
  turnSourceChannel?: string | null;
  turnSourceTo?: string | null;
  turnSourceAccountId?: string | null;
  turnSourceThreadId?: string | number | null;
};

function normalizeOptionalString(value?: string | null): string | null {
  const normalized = value?.trim();
  return normalized ? normalized : null;
}

function normalizeOptionalChannel(value?: string | null): string | null {
  const normalized = normalizeOptionalString(value);
  return normalized ? (normalizeMessageChannel(normalized) ?? normalized.toLowerCase()) : null;
}

function normalizeThreadId(value?: string | number | null): string | null {
  if (typeof value === "number") {
    return Number.isFinite(value) ? String(value) : null;
  }
  const normalized = value?.trim();
  return normalized ? normalized : null;
}

function hasRouteSelector(params: ExecApprovalRouteParams): boolean {
  return Boolean(
    normalizeOptionalString(params.sessionKey) ||
    normalizeOptionalChannel(params.turnSourceChannel) ||
    normalizeOptionalString(params.turnSourceTo) ||
    normalizeOptionalString(params.turnSourceAccountId) ||
    normalizeThreadId(params.turnSourceThreadId),
  );
}

function requestMatchesRoute(
  request: ExecApprovalRequestPayload,
  params: ExecApprovalRouteParams,
): boolean {
  const sessionKey = normalizeOptionalString(params.sessionKey);
  const turnSourceChannel = normalizeOptionalChannel(params.turnSourceChannel);
  const turnSourceTo = normalizeOptionalString(params.turnSourceTo);
  const turnSourceAccountId = normalizeOptionalString(params.turnSourceAccountId);
  const turnSourceThreadId = normalizeThreadId(params.turnSourceThreadId);

  if (sessionKey && normalizeOptionalString(request.sessionKey) !== sessionKey) {
    return false;
  }
  if (
    turnSourceChannel &&
    normalizeOptionalChannel(request.turnSourceChannel) !== turnSourceChannel
  ) {
    return false;
  }
  if (turnSourceTo && normalizeOptionalString(request.turnSourceTo) !== turnSourceTo) {
    return false;
  }
  if (
    turnSourceAccountId &&
    normalizeOptionalString(request.turnSourceAccountId) !== turnSourceAccountId
  ) {
    return false;
  }
  if (turnSourceThreadId && normalizeThreadId(request.turnSourceThreadId) !== turnSourceThreadId) {
    return false;
  }
  return true;
}

export function createExecApprovalHandlers(
  manager: ExecApprovalManager,
  opts?: {
    forwarder?: ExecApprovalForwarder;
    deliverTurnSourcePrompt?: (
      params: DeliverOutboundPayloadsParams,
    ) => ReturnType<typeof deliverOutboundPayloads>;
  },
): GatewayRequestHandlers {
  const deliverTurnSourcePrompt = opts?.deliverTurnSourcePrompt ?? deliverOutboundPayloads;

  const resolveApproval = async (params: {
    approvalId: string;
    decision: ExecApprovalDecision;
    resolvedBy?: string | null;
    snapshot: ReturnType<ExecApprovalManager["getSnapshot"]>;
    respond: (ok: boolean, result?: unknown, error?: unknown) => void;
    context: {
      broadcast: (event: string, payload: unknown, opts?: { dropIfSlow?: boolean }) => void;
      logGateway?: { error?: (message: string) => void };
    };
    result?: Record<string, unknown>;
  }): Promise<void> => {
    const ok = manager.resolve(params.approvalId, params.decision, params.resolvedBy ?? null);
    if (!ok) {
      params.respond(
        false,
        undefined,
        errorShape(ErrorCodes.INVALID_REQUEST, "unknown or expired approval id", {
          details: APPROVAL_NOT_FOUND_DETAILS,
        }),
      );
      return;
    }
    const ts = Date.now();
    params.context.broadcast(
      "exec.approval.resolved",
      {
        id: params.approvalId,
        decision: params.decision,
        resolvedBy: params.resolvedBy,
        ts,
        request: params.snapshot?.request,
      },
      { dropIfSlow: true },
    );
    void opts?.forwarder
      ?.handleResolved({
        id: params.approvalId,
        decision: params.decision,
        resolvedBy: params.resolvedBy,
        ts,
        request: params.snapshot?.request,
      })
      .catch((err) => {
        params.context.logGateway?.error?.(
          `exec approvals: forward resolve failed: ${String(err)}`,
        );
      });
    params.respond(true, params.result ?? { ok: true }, undefined);
  };

  return {
    "exec.approval.request": async ({ params, respond, context, client }) => {
      if (!validateExecApprovalRequestParams(params)) {
        respond(
          false,
          undefined,
          errorShape(
            ErrorCodes.INVALID_REQUEST,
            `invalid exec.approval.request params: ${formatValidationErrors(
              validateExecApprovalRequestParams.errors,
            )}`,
          ),
        );
        return;
      }
      const p = params as {
        id?: string;
        command: string;
        commandArgv?: string[];
        env?: Record<string, string>;
        cwd?: string;
        systemRunPlan?: unknown;
        nodeId?: string;
        host?: string;
        security?: string;
        ask?: string;
        agentId?: string;
        resolvedPath?: string;
        sessionKey?: string;
        turnSourceChannel?: string;
        turnSourceTo?: string;
        turnSourceAccountId?: string;
        turnSourceThreadId?: string | number;
        timeoutMs?: number;
        twoPhase?: boolean;
      };
      const twoPhase = p.twoPhase === true;
      const timeoutMs =
        typeof p.timeoutMs === "number" ? p.timeoutMs : DEFAULT_EXEC_APPROVAL_TIMEOUT_MS;
      const explicitId = typeof p.id === "string" && p.id.trim().length > 0 ? p.id.trim() : null;
      const host = typeof p.host === "string" ? p.host.trim() : "";
      const nodeId = typeof p.nodeId === "string" ? p.nodeId.trim() : "";
      const approvalContext = resolveSystemRunApprovalRequestContext({
        host,
        command: p.command,
        commandArgv: p.commandArgv,
        systemRunPlan: p.systemRunPlan,
        cwd: p.cwd,
        agentId: p.agentId,
        sessionKey: p.sessionKey,
      });
      const effectiveCommandArgv = approvalContext.commandArgv;
      const effectiveCwd = approvalContext.cwd;
      const effectiveAgentId = approvalContext.agentId;
      const effectiveSessionKey = approvalContext.sessionKey;
      const effectiveCommandText = approvalContext.commandText;
      if (host === "node" && !nodeId) {
        respond(
          false,
          undefined,
          errorShape(ErrorCodes.INVALID_REQUEST, "nodeId is required for host=node"),
        );
        return;
      }
      if (host === "node" && !approvalContext.plan) {
        respond(
          false,
          undefined,
          errorShape(ErrorCodes.INVALID_REQUEST, "systemRunPlan is required for host=node"),
        );
        return;
      }
      if (!effectiveCommandText) {
        respond(false, undefined, errorShape(ErrorCodes.INVALID_REQUEST, "command is required"));
        return;
      }
      if (
        host === "node" &&
        (!Array.isArray(effectiveCommandArgv) || effectiveCommandArgv.length === 0)
      ) {
        respond(
          false,
          undefined,
          errorShape(ErrorCodes.INVALID_REQUEST, "commandArgv is required for host=node"),
        );
        return;
      }
      const envBinding = buildSystemRunApprovalEnvBinding(p.env);
      const systemRunBinding =
        host === "node"
          ? buildSystemRunApprovalBinding({
              argv: effectiveCommandArgv,
              cwd: effectiveCwd,
              agentId: effectiveAgentId,
              sessionKey: effectiveSessionKey,
              env: p.env,
            })
          : null;
      if (explicitId && manager.getSnapshot(explicitId)) {
        respond(
          false,
          undefined,
          errorShape(ErrorCodes.INVALID_REQUEST, "approval id already pending"),
        );
        return;
      }
      const request = {
        command: sanitizeExecApprovalDisplayText(effectiveCommandText),
        commandPreview:
          host === "node" || !approvalContext.commandPreview
            ? undefined
            : sanitizeExecApprovalDisplayText(approvalContext.commandPreview),
        commandArgv: host === "node" ? undefined : effectiveCommandArgv,
        envKeys: envBinding.envKeys.length > 0 ? envBinding.envKeys : undefined,
        systemRunBinding: systemRunBinding?.binding ?? null,
        systemRunPlan: approvalContext.plan,
        cwd: effectiveCwd ?? null,
        nodeId: host === "node" ? nodeId : null,
        host: host || null,
        security: p.security ?? null,
        ask: p.ask ?? null,
        agentId: effectiveAgentId ?? null,
        resolvedPath: p.resolvedPath ?? null,
        sessionKey: effectiveSessionKey ?? null,
        turnSourceChannel:
          typeof p.turnSourceChannel === "string" ? p.turnSourceChannel.trim() || null : null,
        turnSourceTo: typeof p.turnSourceTo === "string" ? p.turnSourceTo.trim() || null : null,
        turnSourceAccountId:
          typeof p.turnSourceAccountId === "string" ? p.turnSourceAccountId.trim() || null : null,
        turnSourceThreadId: p.turnSourceThreadId ?? null,
      };
      const record = manager.create(request, timeoutMs, explicitId);
      record.requestedByConnId = client?.connId ?? null;
      record.requestedByDeviceId = client?.connect?.device?.id ?? null;
      record.requestedByClientId = client?.connect?.client?.id ?? null;
      // Use register() to synchronously add to pending map before sending any response.
      // This ensures the approval ID is valid immediately after the "accepted" response.
      let decisionPromise: Promise<
        import("../../infra/exec-approvals.js").ExecApprovalDecision | null
      >;
      try {
        decisionPromise = manager.register(record, timeoutMs);
      } catch (err) {
        respond(
          false,
          undefined,
          errorShape(ErrorCodes.INVALID_REQUEST, `registration failed: ${String(err)}`),
        );
        return;
      }
      context.broadcast(
        "exec.approval.requested",
        {
          id: record.id,
          request: record.request,
          createdAtMs: record.createdAtMs,
          expiresAtMs: record.expiresAtMs,
        },
        { dropIfSlow: true },
      );
      const hasExecApprovalClients = context.hasExecApprovalClients?.(client?.connId) ?? false;
      const hasTurnSourceRoute = hasApprovalTurnSourceRoute({
        turnSourceChannel: record.request.turnSourceChannel,
        turnSourceAccountId: record.request.turnSourceAccountId,
      });
      let forwarded = false;
      if (opts?.forwarder) {
        try {
          forwarded = await opts.forwarder.handleRequested({
            id: record.id,
            request: record.request,
            createdAtMs: record.createdAtMs,
            expiresAtMs: record.expiresAtMs,
          });
        } catch (err) {
          context.logGateway?.error?.(`exec approvals: forward request failed: ${String(err)}`);
        }
      }

      if (!forwarded && hasTurnSourceRoute) {
        const channel = normalizeOptionalChannel(record.request.turnSourceChannel);
        const to = normalizeOptionalString(record.request.turnSourceTo);
        if (channel && isDeliverableMessageChannel(channel) && to) {
          try {
            await deliverTurnSourcePrompt({
              cfg: loadConfig(),
              channel,
              to,
              accountId: normalizeOptionalString(record.request.turnSourceAccountId) ?? undefined,
              threadId: record.request.turnSourceThreadId ?? undefined,
              payloads: [
                buildExecApprovalPendingReplyPayload({
                  approvalId: record.id,
                  approvalSlug: record.id.slice(0, 8),
                  command: record.request.command,
                  cwd: record.request.cwd ?? undefined,
                  host:
                    record.request.host === "sandbox" ||
                    record.request.host === "gateway" ||
                    record.request.host === "node"
                      ? record.request.host
                      : "gateway",
                  nodeId: record.request.nodeId ?? undefined,
                  expiresAtMs: record.expiresAtMs,
                  nowMs: Date.now(),
                }),
              ],
              gatewayClientScopes: ["operator.approvals"],
            });
            forwarded = true;
          } catch (err) {
            context.logGateway?.error?.(
              `exec approvals: turn-source delivery failed: ${String(err)}`,
            );
          }
        }
      }

      if (!hasExecApprovalClients && !forwarded && !hasTurnSourceRoute) {
        manager.expire(record.id, "no-approval-route");
        respond(
          true,
          {
            id: record.id,
            decision: null,
            createdAtMs: record.createdAtMs,
            expiresAtMs: record.expiresAtMs,
          },
          undefined,
        );
        return;
      }

      // Only send immediate "accepted" response when twoPhase is requested.
      // This preserves single-response semantics for existing callers.
      if (twoPhase) {
        respond(
          true,
          {
            status: "accepted",
            id: record.id,
            createdAtMs: record.createdAtMs,
            expiresAtMs: record.expiresAtMs,
          },
          undefined,
        );
      }

      const decision = await decisionPromise;
      // Send final response with decision for callers using expectFinal:true.
      respond(
        true,
        {
          id: record.id,
          decision,
          resolvedBy: manager.getSnapshot(record.id)?.resolvedBy ?? null,
          createdAtMs: record.createdAtMs,
          expiresAtMs: record.expiresAtMs,
        },
        undefined,
      );
    },
    "exec.approval.waitDecision": async ({ params, respond }) => {
      const p = params as { id?: string };
      const id = typeof p.id === "string" ? p.id.trim() : "";
      if (!id) {
        respond(false, undefined, errorShape(ErrorCodes.INVALID_REQUEST, "id is required"));
        return;
      }
      const decisionPromise = manager.awaitDecision(id);
      if (!decisionPromise) {
        respond(
          false,
          undefined,
          errorShape(ErrorCodes.INVALID_REQUEST, "approval expired or not found"),
        );
        return;
      }
      const decision = await decisionPromise;
      const snapshot = manager.getSnapshot(id);
      // Return decision (can be null on timeout) - let clients handle via askFallback
      respond(
        true,
        {
          id,
          decision,
          resolvedBy: snapshot?.resolvedBy ?? null,
          createdAtMs: snapshot?.createdAtMs,
          expiresAtMs: snapshot?.expiresAtMs,
        },
        undefined,
      );
    },
    "exec.approval.resolve": async ({ params, respond, client, context }) => {
      if (!validateExecApprovalResolveParams(params)) {
        respond(
          false,
          undefined,
          errorShape(
            ErrorCodes.INVALID_REQUEST,
            `invalid exec.approval.resolve params: ${formatValidationErrors(
              validateExecApprovalResolveParams.errors,
            )}`,
          ),
        );
        return;
      }
      const p = params as { id: string; decision: string };
      const decision = p.decision as ExecApprovalDecision;
      if (decision !== "allow-once" && decision !== "allow-always" && decision !== "deny") {
        respond(false, undefined, errorShape(ErrorCodes.INVALID_REQUEST, "invalid decision"));
        return;
      }
      const resolvedId = manager.lookupPendingId(p.id);
      if (resolvedId.kind === "none") {
        respond(
          false,
          undefined,
          errorShape(ErrorCodes.INVALID_REQUEST, "unknown or expired approval id", {
            details: APPROVAL_NOT_FOUND_DETAILS,
          }),
        );
        return;
      }
      if (resolvedId.kind === "ambiguous") {
        const candidates = resolvedId.ids.slice(0, 3).join(", ");
        const remainder = resolvedId.ids.length > 3 ? ` (+${resolvedId.ids.length - 3} more)` : "";
        respond(
          false,
          undefined,
          errorShape(
            ErrorCodes.INVALID_REQUEST,
            `ambiguous approval id prefix; matches: ${candidates}${remainder}. Use the full id.`,
          ),
        );
        return;
      }
      const approvalId = resolvedId.id;
      const snapshot = manager.getSnapshot(approvalId);
      const resolvedBy = client?.connect?.client?.displayName ?? client?.connect?.client?.id;
      await resolveApproval({
        approvalId,
        decision,
        resolvedBy,
        snapshot,
        respond,
        context,
      });
    },
    "exec.approval.resolveRoute": async ({ params, respond, client, context }) => {
      if (!validateExecApprovalResolveRouteParams(params)) {
        respond(
          false,
          undefined,
          errorShape(
            ErrorCodes.INVALID_REQUEST,
            `invalid exec.approval.resolveRoute params: ${formatValidationErrors(
              validateExecApprovalResolveRouteParams.errors,
            )}`,
          ),
        );
        return;
      }
      const p = params as ExecApprovalRouteParams & { decision: string };
      const decision = p.decision as ExecApprovalDecision;
      if (decision !== "allow-once" && decision !== "allow-always" && decision !== "deny") {
        respond(false, undefined, errorShape(ErrorCodes.INVALID_REQUEST, "invalid decision"));
        return;
      }
      if (!hasRouteSelector(p)) {
        respond(
          false,
          undefined,
          errorShape(
            ErrorCodes.INVALID_REQUEST,
            "approval route is required for decision-only approvals",
          ),
        );
        return;
      }

      const matches = manager
        .listPendingSnapshots()
        .filter((record) => requestMatchesRoute(record.request, p))
        .toSorted((left, right) => right.createdAtMs - left.createdAtMs);

      if (matches.length === 0) {
        respond(
          false,
          undefined,
          errorShape(
            ErrorCodes.INVALID_REQUEST,
            "no pending exec approval found for this chat; use /approve <id> ...",
            { details: APPROVAL_NOT_FOUND_DETAILS },
          ),
        );
        return;
      }
      if (matches.length > 1) {
        respond(
          false,
          undefined,
          errorShape(
            ErrorCodes.INVALID_REQUEST,
            "multiple pending exec approvals match this chat; use /approve <id> ...",
          ),
        );
        return;
      }

      const approval = matches[0];
      const resolvedBy = client?.connect?.client?.displayName ?? client?.connect?.client?.id;
      await resolveApproval({
        approvalId: approval.id,
        decision,
        resolvedBy,
        snapshot: approval,
        respond,
        context,
        result: { ok: true, id: approval.id },
      });
    },
  };
}
