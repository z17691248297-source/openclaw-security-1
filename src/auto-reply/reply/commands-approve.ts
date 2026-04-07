import {
  isTelegramExecApprovalAuthorizedSender,
  isTelegramExecApprovalClientEnabled,
} from "../../../extensions/telegram/api.js";
import { callGateway } from "../../gateway/call.js";
import { ErrorCodes } from "../../gateway/protocol/index.js";
import { logVerbose } from "../../globals.js";
import { resolveApprovalCommandAuthorization } from "../../infra/channel-approval-auth.js";
import { GATEWAY_CLIENT_MODES, GATEWAY_CLIENT_NAMES } from "../../utils/message-channel.js";
import { requireGatewayClientScopeForInternalChannel } from "./command-gates.js";
import type { CommandHandler } from "./commands-types.js";

const COMMAND_REGEX = /^\/approve(?:\s|$)/i;
const FOREIGN_COMMAND_MENTION_REGEX = /^\/approve@([^\s]+)(?:\s|$)/i;

const DECISION_ALIASES: Record<string, "allow-once" | "allow-always" | "deny"> = {
  allow: "allow-once",
  once: "allow-once",
  "allow-once": "allow-once",
  allowonce: "allow-once",
  always: "allow-always",
  "allow-always": "allow-always",
  allowalways: "allow-always",
  deny: "deny",
  reject: "deny",
  block: "deny",
};

type ParsedApproveCommand =
  | { ok: true; id: string; decision: "allow-once" | "allow-always" | "deny" }
  | { ok: false; error: string };

function parseApprovalDecisionShortcut(raw: string): "allow-once" | "allow-always" | "deny" | null {
  const trimmed = raw.trim();
  if (!trimmed || /\s/.test(trimmed)) {
    return null;
  }
  return DECISION_ALIASES[trimmed.toLowerCase()] ?? null;
}

function parseApproveCommand(raw: string): ParsedApproveCommand | null {
  const trimmed = raw.trim();
  if (FOREIGN_COMMAND_MENTION_REGEX.test(trimmed)) {
    return { ok: false, error: "❌ This /approve command targets a different Telegram bot." };
  }
  const commandMatch = trimmed.match(COMMAND_REGEX);
  if (!commandMatch) {
    return null;
  }
  const rest = trimmed.slice(commandMatch[0].length).trim();
  if (!rest) {
    return { ok: false, error: "Usage: /approve <id> allow-once|allow-always|deny" };
  }
  const tokens = rest.split(/\s+/).filter(Boolean);
  if (tokens.length < 2) {
    return { ok: false, error: "Usage: /approve <id> allow-once|allow-always|deny" };
  }

  const first = tokens[0].toLowerCase();
  const second = tokens[1].toLowerCase();

  if (DECISION_ALIASES[first]) {
    return {
      ok: true,
      decision: DECISION_ALIASES[first],
      id: tokens.slice(1).join(" ").trim(),
    };
  }
  if (DECISION_ALIASES[second]) {
    return {
      ok: true,
      decision: DECISION_ALIASES[second],
      id: tokens[0],
    };
  }
  return { ok: false, error: "Usage: /approve <id> allow-once|allow-always|deny" };
}

function buildResolvedByLabel(params: Parameters<CommandHandler>[0]): string {
  const channel = params.command.channel;
  const sender = params.command.senderId ?? "unknown";
  return `${channel}:${sender}`;
}

function isAuthorizedTelegramExecSender(params: Parameters<CommandHandler>[0]): boolean {
  if (params.command.channel !== "telegram") {
    return false;
  }
  return isTelegramExecApprovalAuthorizedSender({
    cfg: params.cfg,
    accountId: params.ctx.AccountId,
    senderId: params.command.senderId,
  });
}

function readErrorCode(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

function readApprovalNotFoundDetailsReason(value: unknown): string | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  const reason = (value as { reason?: unknown }).reason;
  return typeof reason === "string" && reason.trim() ? reason : null;
}

function isApprovalNotFoundError(err: unknown): boolean {
  if (!(err instanceof Error)) {
    return false;
  }
  const gatewayCode = readErrorCode((err as { gatewayCode?: unknown }).gatewayCode);
  if (gatewayCode === ErrorCodes.APPROVAL_NOT_FOUND) {
    return true;
  }

  const detailsReason = readApprovalNotFoundDetailsReason((err as { details?: unknown }).details);
  if (
    gatewayCode === ErrorCodes.INVALID_REQUEST &&
    detailsReason === ErrorCodes.APPROVAL_NOT_FOUND
  ) {
    return true;
  }

  // Legacy server/client combinations may only include the message text.
  return /unknown or expired approval id/i.test(err.message);
}

export const handleApproveCommand: CommandHandler = async (params, allowTextCommands) => {
  if (!allowTextCommands) {
    return null;
  }
  const normalized = params.command.commandBodyNormalized;
  const parsed = parseApproveCommand(normalized);
  const shortcutDecision = parsed ? null : parseApprovalDecisionShortcut(normalized);
  if (!parsed && !shortcutDecision) {
    return null;
  }
  if (parsed && !parsed.ok) {
    return { shouldContinue: false, reply: { text: parsed.error } };
  }

  const explicitApproval = parsed && parsed.ok ? parsed : null;
  const isPluginId = explicitApproval?.id.startsWith("plugin:") ?? false;
  const telegramExecAuthorizedSender = isAuthorizedTelegramExecSender(params);
  const execApprovalAuthorization = resolveApprovalCommandAuthorization({
    cfg: params.cfg,
    channel: params.command.channel,
    accountId: params.ctx.AccountId,
    senderId: params.command.senderId,
    kind: "exec",
  });
  const pluginApprovalAuthorization = resolveApprovalCommandAuthorization({
    cfg: params.cfg,
    channel: params.command.channel,
    accountId: params.ctx.AccountId,
    senderId: params.command.senderId,
    kind: "plugin",
  });
  const hasExplicitApprovalAuthorization =
    (execApprovalAuthorization.explicit && execApprovalAuthorization.authorized) ||
    (pluginApprovalAuthorization.explicit && pluginApprovalAuthorization.authorized);
  const resolvedBy = buildResolvedByLabel(params);
  const callApprovalMethod = async (method: string): Promise<void> => {
    await callGateway({
      method,
      params: { id: explicitApproval!.id, decision: explicitApproval!.decision },
      clientName: GATEWAY_CLIENT_NAMES.GATEWAY_CLIENT,
      clientDisplayName: `Chat approval (${resolvedBy})`,
      mode: GATEWAY_CLIENT_MODES.BACKEND,
    });
  };

  const resolveCurrentRouteParams = {
    decision: shortcutDecision,
    sessionKey: params.sessionKey,
    turnSourceChannel: params.command.channel,
    turnSourceTo: params.command.to,
    turnSourceAccountId: params.ctx.AccountId,
    turnSourceThreadId: params.ctx.MessageThreadId,
  };

  if (shortcutDecision) {
    if (!params.command.isAuthorizedSender && !hasExplicitApprovalAuthorization) {
      return null;
    }
    if (
      params.command.channel === "telegram" &&
      !telegramExecAuthorizedSender &&
      !isTelegramExecApprovalClientEnabled({ cfg: params.cfg, accountId: params.ctx.AccountId })
    ) {
      return null;
    }
    if (!execApprovalAuthorization.authorized) {
      return null;
    }
    const shortcutMissingScope = requireGatewayClientScopeForInternalChannel(params, {
      label: "/approve",
      allowedScopes: ["operator.approvals", "operator.admin"],
      missingText: "❌ /approve requires operator.approvals for gateway clients.",
    });
    if (shortcutMissingScope) {
      return null;
    }
    try {
      const response = await callGateway({
        method: "exec.approval.resolveRoute",
        params: resolveCurrentRouteParams,
        clientName: GATEWAY_CLIENT_NAMES.GATEWAY_CLIENT,
        clientDisplayName: `Chat approval (${resolvedBy})`,
        mode: GATEWAY_CLIENT_MODES.BACKEND,
      });
      const approvalId =
        response &&
        typeof response === "object" &&
        typeof (response as { id?: unknown }).id === "string"
          ? (response as { id: string }).id
          : undefined;
      return {
        shouldContinue: false,
        reply: {
          text: approvalId
            ? `✅ Approval ${shortcutDecision} submitted for ${approvalId}.`
            : `✅ Approval ${shortcutDecision} submitted.`,
        },
      };
    } catch (err) {
      if (isApprovalNotFoundError(err)) {
        return null;
      }
      return {
        shouldContinue: false,
        reply: { text: `❌ Failed to submit approval: ${String(err)}` },
      };
    }
  }

  if (!params.command.isAuthorizedSender && !hasExplicitApprovalAuthorization) {
    logVerbose(
      `Ignoring /approve from unauthorized sender: ${params.command.senderId || "<unknown>"}`,
    );
    return { shouldContinue: false };
  }

  if (
    params.command.channel === "telegram" &&
    !isPluginId &&
    !telegramExecAuthorizedSender &&
    !isTelegramExecApprovalClientEnabled({ cfg: params.cfg, accountId: params.ctx.AccountId })
  ) {
    return {
      shouldContinue: false,
      reply: { text: "❌ Telegram exec approvals are not enabled for this bot account." },
    };
  }

  if (isPluginId && !pluginApprovalAuthorization.authorized) {
    return {
      shouldContinue: false,
      reply: {
        text:
          pluginApprovalAuthorization.reason ??
          "❌ You are not authorized to approve this request.",
      },
    };
  }

  const missingScope = requireGatewayClientScopeForInternalChannel(params, {
    label: "/approve",
    allowedScopes: ["operator.approvals", "operator.admin"],
    missingText: "❌ /approve requires operator.approvals for gateway clients.",
  });
  if (missingScope) {
    return missingScope;
  }

  // Plugin approval IDs are kind-prefixed (`plugin:<uuid>`); route directly when detected.
  // Unprefixed IDs try the authorized path first, then fall back for backward compat.
  if (isPluginId) {
    try {
      await callApprovalMethod("plugin.approval.resolve");
    } catch (err) {
      return {
        shouldContinue: false,
        reply: { text: `❌ Failed to submit approval: ${String(err)}` },
      };
    }
  } else if (execApprovalAuthorization.authorized) {
    try {
      await callApprovalMethod("exec.approval.resolve");
    } catch (err) {
      if (isApprovalNotFoundError(err)) {
        if (!pluginApprovalAuthorization.authorized) {
          return {
            shouldContinue: false,
            reply: { text: `❌ Failed to submit approval: ${String(err)}` },
          };
        }
        try {
          await callApprovalMethod("plugin.approval.resolve");
        } catch (pluginErr) {
          return {
            shouldContinue: false,
            reply: { text: `❌ Failed to submit approval: ${String(pluginErr)}` },
          };
        }
      } else {
        return {
          shouldContinue: false,
          reply: { text: `❌ Failed to submit approval: ${String(err)}` },
        };
      }
    }
  } else if (pluginApprovalAuthorization.authorized) {
    try {
      await callApprovalMethod("plugin.approval.resolve");
    } catch (err) {
      if (isApprovalNotFoundError(err)) {
        return {
          shouldContinue: false,
          reply: { text: `❌ Failed to submit approval: ${String(err)}` },
        };
      }
      return {
        shouldContinue: false,
        reply: { text: `❌ Failed to submit approval: ${String(err)}` },
      };
    }
  } else {
    return {
      shouldContinue: false,
      reply: {
        text:
          execApprovalAuthorization.reason ?? "❌ You are not authorized to approve this request.",
      },
    };
  }

  return {
    shouldContinue: false,
    reply: {
      text: `✅ Approval ${explicitApproval!.decision} submitted for ${explicitApproval!.id}.`,
    },
  };
};
