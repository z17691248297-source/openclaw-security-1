export type TrustedIsolationRiskLevel = "L0" | "L1" | "L2" | "L3";

export type TrustedIsolationDecision = "dree" | "dia" | "die" | "duc" | "ddeny";

export type TrustedIsolationExecutionMode = "ree-direct" | "ree-constrained" | "isolated";

export type TrustedConfirmationDecision = "approve" | "deny";

export type TrustedConfirmationStatus = "pending" | "approved" | "denied" | "expired";

export type TrustedIsolationAction =
  | "read"
  | "modify"
  | "delete"
  | "exec"
  | "export"
  | "network"
  | "unknown";

export type TrustedPolicyFlag =
  | "destructive"
  | "export"
  | "multi_step"
  | "outside_workspace"
  | "protected_path"
  | "remote_target"
  | "shell_wrapper"
  | "task_mismatch"
  | "user_absent";

export type TrustedObjectClassification = "ordinary" | "sensitive" | "critical";

export type TrustedIsolationOperation = {
  sessionId?: string;
  sessionKey?: string;
  agentId?: string;
  runId?: string;
  toolCallId?: string;
  toolName: string;
  action: TrustedIsolationAction;
  object: string;
  params: Record<string, unknown>;
};

export type TrustedExecScope = {
  matchMode: "exact" | "shell-exact";
  rawCommand: string;
  command: string;
  args: string[];
  cwd?: string;
  envSubset?: Record<string, string>;
};

export type TrustedIsolationScope = {
  action: TrustedIsolationAction;
  target: string;
  allowedPath?: string;
  allowedPrefixes?: string[];
  exec?: TrustedExecScope;
  restrictions?: Record<string, unknown>;
};

export type TrustedIsolationContext = {
  agentId?: string;
  runId?: string;
  toolCallId?: string;
  sessionKey?: string;
  sessionId?: string;
  workdir?: string;
  workspaceRoot?: string;
};

export type TrustedOperationRequest = {
  version: 1;
  reqId: string;
  sid: string;
  seq: number;
  ttlMs: number;
  issuedAtMs: number;
  toolName: string;
  action: TrustedIsolationAction;
  object: string;
  scope: TrustedIsolationScope;
  context: TrustedIsolationContext;
  level: TrustedIsolationRiskLevel;
  normalizedScopeDigest: string;
  requestDigest: string;
};

export type TrustedAuthorizeRequest = TrustedOperationRequest;

export type TrustedPolicyAssessment = {
  actionRisk: {
    level: TrustedIsolationRiskLevel;
    reason: string;
    matchedRuleId: string;
    commandClass?: string;
  };
  objectRisk: {
    level: TrustedIsolationRiskLevel;
    reason: string;
    matchedRuleId: string;
    classification: TrustedObjectClassification;
  };
  contextRisk: {
    level: TrustedIsolationRiskLevel;
    reason: string;
    matchedRuleId: string;
    factors: Record<string, boolean | number | string>;
  };
  effectRisk: {
    level: TrustedIsolationRiskLevel;
    reason: string;
    matchedRuleId: string;
    factors: Record<string, boolean | number | string>;
  };
  contextFlags: Record<TrustedPolicyFlag, boolean>;
  effectFlags: Record<TrustedPolicyFlag, boolean>;
  finalRiskLevel: TrustedIsolationRiskLevel;
  decision: TrustedIsolationDecision;
  reason: string;
  matchedRuleId: string;
};

export type TrustedConfirmationRequirement = {
  confirmationRequestId: string;
  challengeToken: string;
  prompt: string;
  summary: string;
  expiresAtMs: number;
  executionMode: TrustedIsolationExecutionMode;
};

export type TrustedAuthorizeResponse = {
  allow: boolean;
  decision: TrustedIsolationDecision;
  level: TrustedIsolationRiskLevel;
  executionMode: TrustedIsolationExecutionMode;
  reason: string;
  matchedRuleId: string;
  normalizedRequest: TrustedOperationRequest;
  classification: TrustedPolicyAssessment;
  constraints?: Record<string, unknown>;
  scopeToken?: string;
  confirmation?: TrustedConfirmationRequirement;
  evidence?: Record<string, unknown>;
};

export type TrustedScopeTokenPayload = {
  version: 1;
  reqId: string;
  sid: string;
  action: TrustedIsolationAction;
  object: string;
  scope: TrustedIsolationScope;
  normalizedScopeDigest: string;
  issuedAtMs: number;
  expiresAtMs: number;
};

export type TrustedScopeEnvelope = {
  reqId: string;
  sid: string;
  token: string;
  action: TrustedIsolationAction;
  object: string;
  level: TrustedIsolationRiskLevel;
  normalizedScopeDigest: string;
  issuedAtMs: number;
  expiresAtMs: number;
  constraints?: Record<string, unknown>;
};

export type TrustedPendingExecution = {
  key: string;
  request: TrustedOperationRequest;
  response: TrustedAuthorizeResponse;
  scopeToken?: string;
  startedAtMs: number;
  backendBaseUrl?: string;
  confirmationRequestId?: string;
  confirmationStatus?: TrustedConfirmationStatus;
  confirmedBy?: string;
};

export type TrustedConfirmRequest = {
  confirmationRequestId: string;
  challengeToken: string;
  operatorId: string;
  decision: TrustedConfirmationDecision;
  reason?: string;
  context?: Record<string, unknown>;
};

export type TrustedConfirmResponse = {
  ok: boolean;
  confirmationRequestId: string;
  status: TrustedConfirmationStatus;
  decision: TrustedIsolationDecision;
  level: TrustedIsolationRiskLevel;
  executionMode: TrustedIsolationExecutionMode;
  reason: string;
  matchedRuleId: string;
  normalizedRequest: TrustedOperationRequest;
  confirmedAtMs: number;
  operatorId: string;
  scopeToken?: string;
  evidence?: Record<string, unknown>;
};

export type TrustedCompleteRequest = {
  reqId: string;
  sid: string;
  toolName: string;
  action: TrustedIsolationAction;
  object: string;
  level: TrustedIsolationRiskLevel;
  decision: TrustedIsolationDecision;
  executionMode: TrustedIsolationExecutionMode;
  matchedRuleId: string;
  normalizedScopeDigest: string;
  requestDigest: string;
  startedAtMs: number;
  finishedAtMs: number;
  durationMs: number;
  status: "ok" | "error" | "violation";
  resultDigest: string;
  errorCode?: string;
  errorMessage?: string;
  confirmationRequestId?: string;
  confirmationStatus?: TrustedConfirmationStatus;
  confirmedBy?: string;
  context: TrustedIsolationContext;
};

export type TrustedEvidenceEvent =
  | "authorize"
  | "backend_error"
  | "complete"
  | "confirm"
  | "deny"
  | "violation";

export type TrustedEvidenceRecord = {
  event: TrustedEvidenceEvent;
  ts: number;
  reqId: string;
  sid: string;
  toolName: string;
  action: TrustedIsolationAction;
  object: string;
  level: TrustedIsolationRiskLevel;
  decision: TrustedIsolationDecision;
  executionMode?: TrustedIsolationExecutionMode;
  matchedRuleId?: string;
  normalizedScopeDigest: string;
  requestDigest: string;
  status: string;
  durationMs?: number;
  resultDigest?: string;
  errorCode?: string;
  errorMessage?: string;
  backendStage?: "authorize" | "complete";
  confirmationRequestId?: string;
  confirmationStatus?: TrustedConfirmationStatus;
  confirmedBy?: string;
  context?: TrustedIsolationContext;
  evidence?: Record<string, unknown>;
  prevHash?: string;
  entryHash?: string;
};
