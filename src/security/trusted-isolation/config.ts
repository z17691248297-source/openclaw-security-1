import { resolveAgentConfig } from "../../agents/agent-scope.js";
import { loadConfig } from "../../config/config.js";
import type { TrustedIsolationAction } from "./types.js";

export type TrustedIsolationConfig = {
  enabled: boolean;
  enforceFailClosed: boolean;
  backendBaseUrl?: string;
  authorizePath: string;
  completePath: string;
  requestTimeoutMs: number;
  verifyMode: "none" | "hmac-sha256" | "ed25519";
  hmacKey?: string;
  publicKeyPem?: string;
  requireScopeToken: boolean;
  ttlMs: number;
  riskThresholds: Record<"low" | "medium" | "high" | "critical", number>;
  actionScores: Record<TrustedIsolationAction, number>;
  contextScores: {
    outsideWorkspace: number;
    untrustedSource: number;
    noUserConfirmation: number;
  };
  effectScores: {
    persistence: number;
    exfiltration: number;
    privilegeEscalation: number;
  };
  levelToDecision: Record<
    "low" | "medium" | "high" | "critical",
    "direct" | "notify" | "trusted" | "deny"
  >;
  forceTrustedActions: TrustedIsolationAction[];
  forceTrustedTools: string[];
  protectedPathPrefixes: string[];
  denyObjectPrefixes: string[];
  evidenceFile?: string;
};

type TrustedIsolationConfigInput = {
  enabled?: boolean;
  enforceFailClosed?: boolean;
  backendBaseUrl?: string;
  authorizePath?: string;
  completePath?: string;
  requestTimeoutMs?: number;
  verify?: {
    mode?: "none" | "hmac-sha256" | "ed25519";
    hmacKey?: string;
    publicKeyPem?: string;
    requireScopeToken?: boolean;
  };
  ttlMs?: number;
  riskThresholds?: Partial<Record<"low" | "medium" | "high" | "critical", number>>;
  actionScores?: Partial<Record<TrustedIsolationAction, number>>;
  contextScores?: {
    outsideWorkspace?: number;
    untrustedSource?: number;
    noUserConfirmation?: number;
  };
  effectScores?: {
    persistence?: number;
    exfiltration?: number;
    privilegeEscalation?: number;
  };
  levelToDecision?: Partial<
    Record<"low" | "medium" | "high" | "critical", "direct" | "notify" | "trusted" | "deny">
  >;
  forceTrustedActions?: TrustedIsolationAction[];
  forceTrustedTools?: string[];
  protectedPathPrefixes?: string[];
  denyObjectPrefixes?: string[];
  evidenceFile?: string;
};

const DEFAULT_CONFIG: TrustedIsolationConfig = {
  enabled: false,
  enforceFailClosed: true,
  backendBaseUrl: undefined,
  authorizePath: "/v1/trusted/authorize",
  completePath: "/v1/trusted/complete",
  requestTimeoutMs: 5000,
  verifyMode: "none",
  hmacKey: undefined,
  publicKeyPem: undefined,
  requireScopeToken: true,
  ttlMs: 15000,
  riskThresholds: {
    low: 0,
    medium: 25,
    high: 50,
    critical: 80,
  },
  actionScores: {
    read: 5,
    modify: 40,
    delete: 65,
    exec: 70,
    export: 80,
    network: 60,
    unknown: 35,
  },
  contextScores: {
    outsideWorkspace: 25,
    untrustedSource: 20,
    noUserConfirmation: 10,
  },
  effectScores: {
    persistence: 15,
    exfiltration: 35,
    privilegeEscalation: 35,
  },
  levelToDecision: {
    low: "direct",
    medium: "notify",
    high: "trusted",
    critical: "deny",
  },
  forceTrustedActions: ["exec"],
  forceTrustedTools: [],
  protectedPathPrefixes: ["/etc", "/var/lib", "/root/.ssh"],
  denyObjectPrefixes: ["/root/.ssh"],
  evidenceFile: undefined,
};

function sanitizePath(pathValue: string | undefined, fallback: string): string {
  const normalized = pathValue?.trim();
  if (!normalized) {
    return fallback;
  }
  return normalized.startsWith("/") ? normalized : `/${normalized}`;
}

function mergeConfig(
  base: TrustedIsolationConfig,
  override?: TrustedIsolationConfigInput,
): TrustedIsolationConfig {
  if (!override) {
    return base;
  }
  return {
    ...base,
    enabled: override.enabled ?? base.enabled,
    enforceFailClosed: override.enforceFailClosed ?? base.enforceFailClosed,
    backendBaseUrl: override.backendBaseUrl?.trim() || base.backendBaseUrl,
    authorizePath: sanitizePath(override.authorizePath, base.authorizePath),
    completePath: sanitizePath(override.completePath, base.completePath),
    requestTimeoutMs: override.requestTimeoutMs ?? base.requestTimeoutMs,
    verifyMode: override.verify?.mode ?? base.verifyMode,
    hmacKey: override.verify?.hmacKey ?? base.hmacKey,
    publicKeyPem: override.verify?.publicKeyPem ?? base.publicKeyPem,
    requireScopeToken: override.verify?.requireScopeToken ?? base.requireScopeToken,
    ttlMs: override.ttlMs ?? base.ttlMs,
    riskThresholds: {
      ...base.riskThresholds,
      ...(override.riskThresholds ?? {}),
    },
    actionScores: {
      ...base.actionScores,
      ...(override.actionScores ?? {}),
    },
    contextScores: {
      ...base.contextScores,
      ...(override.contextScores ?? {}),
    },
    effectScores: {
      ...base.effectScores,
      ...(override.effectScores ?? {}),
    },
    levelToDecision: {
      ...base.levelToDecision,
      ...(override.levelToDecision ?? {}),
    },
    forceTrustedActions: Array.isArray(override.forceTrustedActions)
      ? override.forceTrustedActions
      : base.forceTrustedActions,
    forceTrustedTools: Array.isArray(override.forceTrustedTools)
      ? override.forceTrustedTools
      : base.forceTrustedTools,
    protectedPathPrefixes: Array.isArray(override.protectedPathPrefixes)
      ? override.protectedPathPrefixes
      : base.protectedPathPrefixes,
    denyObjectPrefixes: Array.isArray(override.denyObjectPrefixes)
      ? override.denyObjectPrefixes
      : base.denyObjectPrefixes,
    evidenceFile: override.evidenceFile ?? base.evidenceFile,
  };
}

export function resolveTrustedIsolationConfig(agentId?: string): TrustedIsolationConfig {
  const cfg = loadConfig();
  const globalInput = (cfg.tools?.trustedIsolation ?? undefined) as
    | TrustedIsolationConfigInput
    | undefined;
  const agentInput = (
    agentId ? resolveAgentConfig(cfg, agentId)?.tools?.trustedIsolation : undefined
  ) as TrustedIsolationConfigInput | undefined;
  return mergeConfig(mergeConfig(DEFAULT_CONFIG, globalInput), agentInput);
}
