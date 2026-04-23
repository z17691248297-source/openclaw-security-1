import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";

const RISK_ORDER = ["L0", "L1", "L2", "L3"];
const CRITICAL_KEYWORDS = ["credential", "private_key", "secret", "token"];
const SENSITIVE_FILENAMES = new Set([".env", "config.json", "config.yaml", "settings.json"]);
const REMOTE_COMMANDS = ["curl", "nc", "ncat", "rsync", "scp", "ssh", "wget"];
const DESTRUCTIVE_COMMANDS = [
  "chown",
  "dd",
  "iptables",
  "mount",
  "rm",
  "service",
  "sudo",
  "systemctl",
  "ufw",
  "umount",
];
const ARCHIVE_COMMANDS = ["tar", "zip"];
const PERSISTENCE_COMMANDS = ["chmod", "cp", "mkdir", "mv", "sed", "tar", "zip"];
const PRIVILEGE_MUTATION_COMMANDS = [
  "chmod",
  "chown",
  "iptables",
  "mount",
  "service",
  "systemctl",
  "ufw",
];

export const DEFAULT_TRUSTED_POLICY = {
  version: 1,
  exec: {
    decisionMap: {
      L0: "dree",
      L1: "dia",
      L2: "die",
      L3: "ddeny",
    },
    lowRiskCommands: [
      "cut",
      "echo",
      "false",
      "head",
      "ls",
      "printf",
      "pwd",
      "sort",
      "tail",
      "tr",
      "true",
      "uniq",
      "wc",
    ],
    mediumReadCommands: ["cat", "find", "grep"],
    mediumModifyCommands: ["awk", "chmod", "cp", "mkdir", "mv", "sed", "tar", "zip"],
    highRiskCommands: [
      "bash",
      "curl",
      "dd",
      "iptables",
      "mount",
      "nc",
      "ncat",
      "node",
      "perl",
      "python",
      "rm",
      "rsync",
      "scp",
      "service",
      "sh",
      "ssh",
      "su",
      "sudo",
      "systemctl",
      "ufw",
      "umount",
      "wget",
      "zsh",
    ],
    confirmableCommands: ["rsync", "scp", "tar", "zip"],
    criticalPathPrefixes: ["/etc", "/var/lib", "~/.aws", "~/.config/gcloud", "~/.ssh"],
    sensitivePathPrefixes: ["/home", "/root", "~/.config"],
    protectedPathKeywords: [...CRITICAL_KEYWORDS, "auth", "credential", "private", "ssh"],
    pathSemantics: {
      redirectionOnlyCommands: ["echo", "false", "printf", "pwd", "true"],
      skipLeadingOperands: {
        awk: 1,
        chmod: 1,
        chown: 1,
        grep: 1,
        sed: 1,
      },
    },
  },
};

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function normalizePathish(value) {
  return String(value || "").replace(/\\/g, "/");
}

function trimText(value) {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function riskIndex(level) {
  return Math.max(0, RISK_ORDER.indexOf(level));
}

function maxRisk(...levels) {
  return levels.reduce((highest, current) => {
    return riskIndex(current) > riskIndex(highest) ? current : highest;
  }, "L0");
}

function executionModeForDecision(decision) {
  if (decision === "dree") {
    return "ree-direct";
  }
  if (decision === "dia") {
    return "ree-constrained";
  }
  if (decision === "die") {
    return "isolated";
  }
  return "ree-constrained";
}

export function decisionForConfirmedExecutionMode(executionMode) {
  if (executionMode === "ree-direct") {
    return "dree";
  }
  if (executionMode === "isolated") {
    return "die";
  }
  return "dia";
}

function mergePolicy(base, override) {
  if (!override || typeof override !== "object") {
    return clone(base);
  }
  const merged = clone(base);
  if (override.exec && typeof override.exec === "object") {
    const nextExec = override.exec;
    merged.exec = {
      ...merged.exec,
      ...nextExec,
      decisionMap: {
        ...merged.exec.decisionMap,
        ...(nextExec.decisionMap && typeof nextExec.decisionMap === "object"
          ? nextExec.decisionMap
          : {}),
      },
      pathSemantics: {
        ...merged.exec.pathSemantics,
        ...(nextExec.pathSemantics && typeof nextExec.pathSemantics === "object"
          ? nextExec.pathSemantics
          : {}),
        skipLeadingOperands: {
          ...merged.exec.pathSemantics.skipLeadingOperands,
          ...(nextExec.pathSemantics &&
          typeof nextExec.pathSemantics === "object" &&
          nextExec.pathSemantics.skipLeadingOperands &&
          typeof nextExec.pathSemantics.skipLeadingOperands === "object"
            ? nextExec.pathSemantics.skipLeadingOperands
            : {}),
        },
      },
    };
  }
  return merged;
}

export async function loadTrustedPolicy(policyPath) {
  if (!trimText(policyPath)) {
    return clone(DEFAULT_TRUSTED_POLICY);
  }
  const raw = await fs.readFile(path.resolve(policyPath), "utf8");
  return mergePolicy(DEFAULT_TRUSTED_POLICY, JSON.parse(raw));
}

function normalizeRequestLevel(request, level) {
  const normalizedRequest = {
    ...request,
    level,
  };
  return {
    ...normalizedRequest,
    requestDigest: createRequestDigest(normalizedRequest),
  };
}

function createRequestDigest(request) {
  const { requestDigest: _ignored, ...rest } = request;
  return crypto.createHash("sha256").update(JSON.stringify(rest)).digest("hex");
}

function isUrl(value) {
  return /^https?:\/\//i.test(String(value || ""));
}

function isRemoteSpec(value) {
  return /^[A-Za-z0-9._-]+@[^:]+:/.test(String(value || ""));
}

function isProtectedKeywordPath(value, policy) {
  const normalized = normalizePathish(value).toLowerCase();
  return policy.exec.protectedPathKeywords.some((keyword) => normalized.includes(keyword));
}

function isShellExactExecScope(request) {
  return request?.scope?.exec?.matchMode === "shell-exact";
}

function normalizeRawShellCommand(request) {
  return normalizePathish(trimText(request?.scope?.exec?.rawCommand) || "");
}

function hasWordToken(command, token) {
  const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(^|[^A-Za-z0-9_./~-])${escaped}($|[^A-Za-z0-9_./~-])`, "i").test(command);
}

function rawCommandContainsAnyToken(command, tokens) {
  return tokens.some((token) => hasWordToken(command, token));
}

function classifyShellExactObjectRisk(request, policy) {
  const rawCommand = normalizeRawShellCommand(request);
  const normalizedRaw = rawCommand.toLowerCase();
  if (
    policy.exec.criticalPathPrefixes.some((prefix) =>
      normalizedRaw.includes(normalizePathish(prefix).toLowerCase()),
    ) ||
    isProtectedKeywordPath(rawCommand, policy)
  ) {
    return {
      level: "L3",
      reason: "critical object referenced from shell compound",
      matchedRuleId: "object.critical.shell-compound",
      classification: "critical",
    };
  }
  if (
    [...SENSITIVE_FILENAMES].some((fileName) => hasWordToken(rawCommand, fileName)) ||
    policy.exec.sensitivePathPrefixes.some((prefix) =>
      normalizedRaw.includes(normalizePathish(prefix).toLowerCase()),
    )
  ) {
    return {
      level: "L2",
      reason: "sensitive object referenced from shell compound",
      matchedRuleId: "object.sensitive.shell-compound",
      classification: "sensitive",
    };
  }
  return {
    level: "L0",
    reason: "ordinary workspace object target",
    matchedRuleId: "object.ordinary.workspace",
    classification: "ordinary",
  };
}

function resolvePathTarget(target, cwd) {
  const value = trimText(target);
  if (!value || value.startsWith("-") || isUrl(value) || isRemoteSpec(value)) {
    return null;
  }
  if (value.startsWith("~/")) {
    return value;
  }
  if (path.isAbsolute(value)) {
    return path.resolve(value);
  }
  if (trimText(cwd)) {
    return path.resolve(cwd, value);
  }
  return value;
}

const REDIRECTION_TOKENS = new Set([">", ">>", "1>", "1>>", "2>", "2>>", "<", "0<"]);

function extractInlineRedirectionTarget(value) {
  const match = String(value || "").match(/^(?:(?:\d*)>>?|<)(.+)$/);
  if (!match) {
    return null;
  }
  const target = trimText(match[1]);
  if (!target || target.startsWith("<") || target.startsWith(">")) {
    return null;
  }
  return target;
}

function collectRedirectionTargets(args, cwd) {
  const targets = [];
  for (let index = 0; index < args.length; index += 1) {
    const value = trimText(args[index]);
    if (!value) {
      continue;
    }
    if (REDIRECTION_TOKENS.has(value)) {
      const redirectedTarget = resolvePathTarget(args[index + 1], cwd);
      if (redirectedTarget) {
        targets.push(redirectedTarget);
      }
      index += 1;
      continue;
    }
    const inlineTarget = extractInlineRedirectionTarget(value);
    if (inlineTarget) {
      const redirectedTarget = resolvePathTarget(inlineTarget, cwd);
      if (redirectedTarget) {
        targets.push(redirectedTarget);
      }
    }
  }
  return targets;
}

function collectPositionalExecArgs(args) {
  const positionalArgs = [];
  let afterDoubleDash = false;
  for (let index = 0; index < args.length; index += 1) {
    const value = trimText(args[index]);
    if (!value) {
      continue;
    }
    if (REDIRECTION_TOKENS.has(value)) {
      index += 1;
      continue;
    }
    if (extractInlineRedirectionTarget(value)) {
      continue;
    }
    if (!afterDoubleDash && value === "--") {
      afterDoubleDash = true;
      continue;
    }
    if (!afterDoubleDash && value.startsWith("-")) {
      continue;
    }
    positionalArgs.push(value);
  }
  return positionalArgs;
}

function dedupeTargets(targets) {
  return [...new Set(targets)];
}

function collectExecTargets(request, policy) {
  const args = Array.isArray(request?.scope?.exec?.args) ? request.scope.exec.args : [];
  const cwd = request?.scope?.exec?.cwd ?? request?.context?.workdir;
  const base = path.posix.basename(trimText(request?.scope?.exec?.command) || "");
  const redirectionTargets = collectRedirectionTargets(args, cwd);
  const redirectionOnlyCommands = Array.isArray(
    policy?.exec?.pathSemantics?.redirectionOnlyCommands,
  )
    ? policy.exec.pathSemantics.redirectionOnlyCommands
    : [];
  const skipLeadingOperands =
    policy?.exec?.pathSemantics?.skipLeadingOperands &&
    typeof policy.exec.pathSemantics.skipLeadingOperands === "object"
      ? Number(policy.exec.pathSemantics.skipLeadingOperands[base] ?? 0)
      : 0;
  const positionalArgs = redirectionOnlyCommands.includes(base)
    ? []
    : collectPositionalExecArgs(args).slice(Math.max(0, skipLeadingOperands));
  const targets = dedupeTargets([
    ...redirectionTargets,
    ...positionalArgs.map((arg) => resolvePathTarget(arg, cwd)).filter(Boolean),
  ]);
  return targets.length > 0 ? targets : [cwd].filter(Boolean);
}

function isWithinWorkspace(target, workspaceRoot) {
  const normalizedTarget = trimText(target);
  const normalizedWorkspaceRoot = trimText(workspaceRoot);
  if (!normalizedTarget || !normalizedWorkspaceRoot || normalizedTarget.startsWith("~/")) {
    return false;
  }
  const resolvedTarget = path.resolve(normalizedTarget);
  const resolvedWorkspaceRoot = path.resolve(normalizedWorkspaceRoot);
  const relative = path.relative(resolvedWorkspaceRoot, resolvedTarget);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

function classifyActionRisk(request, policy) {
  if (isShellExactExecScope(request)) {
    return {
      level: "L2",
      reason: "compound shell command requires isolated execution",
      matchedRuleId: "exec.action.shell-compound",
      commandClass: "shell-compound",
    };
  }
  const base = path.posix.basename(trimText(request?.scope?.exec?.command) || "");
  if (policy.exec.lowRiskCommands.includes(base)) {
    return {
      level: "L1",
      reason: `low-risk exec command ${base}`,
      matchedRuleId: "exec.action.low-risk",
      commandClass: "low-risk",
    };
  }
  if (policy.exec.mediumReadCommands.includes(base)) {
    return {
      level: "L1",
      reason: `read-like exec command ${base}`,
      matchedRuleId: "exec.action.medium-read",
      commandClass: "medium-read",
    };
  }
  if (policy.exec.mediumModifyCommands.includes(base)) {
    return {
      level: "L2",
      reason: `state-modifying exec command ${base}`,
      matchedRuleId: "exec.action.medium-modify",
      commandClass: "medium-modify",
    };
  }
  if (policy.exec.highRiskCommands.includes(base)) {
    return {
      level: "L3",
      reason: `high-risk exec command ${base}`,
      matchedRuleId: "exec.action.high-risk",
      commandClass: "high-risk",
    };
  }
  return {
    level: "L2",
    reason: `unclassified exec command ${base || "unknown"}`,
    matchedRuleId: "exec.action.unknown",
    commandClass: "unknown",
  };
}

function classifyObjectRisk(request, policy) {
  if (isShellExactExecScope(request)) {
    return classifyShellExactObjectRisk(request, policy);
  }
  const workspaceRoot = trimText(request?.context?.workspaceRoot);
  const targets = collectExecTargets(request, policy);
  for (const target of targets) {
    const normalized = normalizePathish(target);
    if (
      policy.exec.criticalPathPrefixes.some((prefix) =>
        normalized.startsWith(normalizePathish(prefix)),
      ) ||
      isProtectedKeywordPath(target, policy)
    ) {
      return {
        level: "L3",
        reason: `critical object target ${normalized}`,
        matchedRuleId: "object.critical.protected-path",
        classification: "critical",
      };
    }
  }
  for (const target of targets) {
    const normalized = normalizePathish(target);
    const base = path.posix.basename(normalized);
    const hiddenSegment = normalized
      .split("/")
      .some((segment) => segment.startsWith(".") && segment.length > 1);
    const insideWorkspace = isWithinWorkspace(target, workspaceRoot);
    const outsideWorkspace = Boolean(workspaceRoot) && !insideWorkspace;
    const matchesSensitivePrefix =
      (!workspaceRoot || outsideWorkspace) &&
      policy.exec.sensitivePathPrefixes.some((prefix) =>
        normalized.startsWith(normalizePathish(prefix)),
      );
    const sensitiveFilename = SENSITIVE_FILENAMES.has(base);
    if (hiddenSegment || outsideWorkspace || matchesSensitivePrefix || sensitiveFilename) {
      const matchedRuleId = hiddenSegment
        ? "object.sensitive.hidden-path"
        : sensitiveFilename
          ? "object.sensitive.filename"
          : outsideWorkspace
            ? "object.sensitive.non-workspace"
            : "object.sensitive.user-path";
      return {
        level: "L2",
        reason: `sensitive object target ${normalized}`,
        matchedRuleId,
        classification: "sensitive",
      };
    }
  }
  return {
    level: "L0",
    reason: "ordinary workspace object target",
    matchedRuleId: "object.ordinary.workspace",
    classification: "ordinary",
  };
}

function classifyContextRisk(request, policy, objectRisk) {
  const rawCommand = trimText(request?.scope?.exec?.rawCommand) || "";
  const base = path.posix.basename(trimText(request?.scope?.exec?.command) || "");
  const args = Array.isArray(request?.scope?.exec?.args) ? request.scope.exec.args : [];
  const execTargets = isShellExactExecScope(request) ? [] : collectExecTargets(request, policy);
  const workspaceRoot = trimText(request?.context?.workspaceRoot);
  const inlineCode =
    ((base === "bash" || base === "sh" || base === "zsh") && args.includes("-c")) ||
    (base === "python" && args.includes("-c")) ||
    (base === "perl" && args.includes("-e")) ||
    (base === "node" && args.includes("-e"));
  const multiStep = isShellExactExecScope(request) || /(?:&&|\|\||;|\n|\r)/.test(rawCommand);
  const remoteTarget =
    REMOTE_COMMANDS.includes(base) ||
    rawCommandContainsAnyToken(rawCommand, REMOTE_COMMANDS) ||
    args.some((arg) => isUrl(arg) || isRemoteSpec(arg));
  const outsideWorkspace =
    Boolean(workspaceRoot) &&
    execTargets.some((target) => !isWithinWorkspace(target, workspaceRoot));
  const taskMismatch = false;
  const userAbsent =
    !trimText(request?.context?.sessionKey) && !trimText(request?.context?.sessionId);
  const factors = {
    multi_step: multiStep,
    outside_workspace: outsideWorkspace,
    remote_target: remoteTarget,
    shell_wrapper: inlineCode || ["bash", "sh", "zsh"].includes(base),
    task_mismatch: taskMismatch,
    user_absent: userAbsent,
    target_count: execTargets.length,
    object_classification: objectRisk.classification,
  };

  if (remoteTarget) {
    return {
      level: "L3",
      reason: "remote target or remote transfer context",
      matchedRuleId: "context.remote-target",
      factors,
    };
  }
  if (factors.shell_wrapper) {
    return {
      level: "L3",
      reason: "shell wrapper or inline interpreter context",
      matchedRuleId: "context.shell-wrapper",
      factors,
    };
  }
  if (multiStep && outsideWorkspace) {
    return {
      level: "L3",
      reason: "multi-step command spans outside the workspace",
      matchedRuleId: "context.multi-step.non-workspace",
      factors,
    };
  }
  if (multiStep) {
    return {
      level: "L2",
      reason: "multi-step command context",
      matchedRuleId: "context.multi-step",
      factors,
    };
  }
  if (outsideWorkspace) {
    return {
      level: "L2",
      reason: "non-workspace execution context",
      matchedRuleId: "context.non-workspace",
      factors,
    };
  }
  if (userAbsent || execTargets.length > 1) {
    return {
      level: "L1",
      reason: "reduced operator context or multi-target command",
      matchedRuleId: "context.reduced-operator",
      factors,
    };
  }
  return {
    level: "L0",
    reason: "ordinary workspace execution context",
    matchedRuleId: "context.workspace.ordinary",
    factors,
  };
}

function classifyEffectRisk(request, actionRisk, objectRisk, contextRisk) {
  const rawCommand = trimText(request?.scope?.exec?.rawCommand) || "";
  const base = path.posix.basename(trimText(request?.scope?.exec?.command) || "");
  const destructive =
    DESTRUCTIVE_COMMANDS.includes(base) ||
    rawCommandContainsAnyToken(rawCommand, DESTRUCTIVE_COMMANDS) ||
    /\brm\s+-rf\b/i.test(rawCommand);
  const exportLike =
    REMOTE_COMMANDS.includes(base) ||
    ARCHIVE_COMMANDS.includes(base) ||
    rawCommandContainsAnyToken(rawCommand, REMOTE_COMMANDS);
  const privilegeMutation =
    PRIVILEGE_MUTATION_COMMANDS.includes(base) ||
    (objectRisk.classification === "critical" && ["chmod", "chown"].includes(base));
  const persistence =
    PERSISTENCE_COMMANDS.includes(base) ||
    (actionRisk.commandClass === "medium-modify" && objectRisk.classification !== "ordinary");
  const factors = {
    export: exportLike,
    destructive,
    persistence,
    privilege_mutation: privilegeMutation,
    archive_packaging: ARCHIVE_COMMANDS.includes(base),
    remote_target: Boolean(contextRisk?.factors?.remote_target),
    object_classification: objectRisk.classification,
  };

  if (destructive && objectRisk.classification !== "ordinary") {
    return {
      level: "L3",
      reason: "destructive effect against a sensitive or critical target",
      matchedRuleId: "effect.destructive.sensitive-target",
      factors,
    };
  }
  if (exportLike) {
    return {
      level: "L3",
      reason: "data packaging, export, or remote transfer effect",
      matchedRuleId: "effect.export-or-archive",
      factors,
    };
  }
  if (privilegeMutation) {
    return {
      level: "L3",
      reason: "privilege or system-state mutation effect",
      matchedRuleId: "effect.privilege-mutation",
      factors,
    };
  }
  if (destructive) {
    return {
      level: "L2",
      reason: "destructive local effect",
      matchedRuleId: "effect.destructive.local",
      factors,
    };
  }
  if (persistence) {
    return {
      level: "L2",
      reason: "persistent filesystem or state mutation effect",
      matchedRuleId: "effect.persistence",
      factors,
    };
  }
  if (actionRisk.commandClass === "medium-read") {
    return {
      level: "L1",
      reason: "bounded read effect",
      matchedRuleId: "effect.read-bounded",
      factors,
    };
  }
  return {
    level: "L0",
    reason: "transient or low-impact effect",
    matchedRuleId: "effect.transient.low",
    factors,
  };
}

function flagsFromAssessment(objectRisk, contextRisk, effectRisk) {
  const contextFlags = {
    destructive: Boolean(effectRisk?.factors?.destructive),
    export: Boolean(effectRisk?.factors?.export),
    multi_step: Boolean(contextRisk?.factors?.multi_step),
    outside_workspace: Boolean(contextRisk?.factors?.outside_workspace),
    protected_path: objectRisk.classification === "critical",
    remote_target: Boolean(contextRisk?.factors?.remote_target),
    shell_wrapper: Boolean(contextRisk?.factors?.shell_wrapper),
    task_mismatch: Boolean(contextRisk?.factors?.task_mismatch),
    user_absent: Boolean(contextRisk?.factors?.user_absent),
  };
  const effectFlags = {
    destructive: Boolean(effectRisk?.factors?.destructive),
    export: Boolean(effectRisk?.factors?.export),
    multi_step: Boolean(contextRisk?.factors?.multi_step),
    outside_workspace: Boolean(contextRisk?.factors?.outside_workspace),
    protected_path: objectRisk.classification === "critical",
    remote_target: Boolean(effectRisk?.factors?.remote_target),
    shell_wrapper: Boolean(contextRisk?.factors?.shell_wrapper),
    task_mismatch: Boolean(contextRisk?.factors?.task_mismatch),
    user_absent: Boolean(contextRisk?.factors?.user_absent),
  };
  return { contextFlags, effectFlags };
}

function matchPatternRule(request, flags) {
  const rawCommand = trimText(request?.scope?.exec?.rawCommand) || "";
  const base = path.posix.basename(trimText(request?.scope?.exec?.command) || "");
  if (/(curl|wget)\b[^|]*\|\s*(bash|sh|zsh)\b/i.test(rawCommand)) {
    return {
      level: "L3",
      decision: "ddeny",
      reason: "remote fetch execution is denied",
      matchedRuleId: "exec.pattern.remote-fetch-shell",
    };
  }
  if (
    (base === "bash" || base === "sh" || base === "zsh") &&
    request?.scope?.exec?.args?.includes("-c")
  ) {
    return {
      level: "L3",
      decision: "ddeny",
      reason: "shell wrapper inline execution is denied",
      matchedRuleId: "exec.pattern.shell-inline",
    };
  }
  if (
    (base === "python" && request?.scope?.exec?.args?.includes("-c")) ||
    (base === "node" && request?.scope?.exec?.args?.includes("-e")) ||
    (base === "perl" && request?.scope?.exec?.args?.includes("-e"))
  ) {
    return {
      level: "L3",
      decision: "ddeny",
      reason: "inline code execution is denied",
      matchedRuleId: "exec.pattern.inline-code",
    };
  }
  if (/\brm\s+-rf\b/i.test(rawCommand)) {
    return {
      level: "L3",
      decision: "ddeny",
      reason: "destructive recursive removal is denied",
      matchedRuleId: "exec.pattern.rm-rf",
    };
  }
  if (flags.contextFlags.protected_path && (base === "chmod" || base === "chown")) {
    return {
      level: "L3",
      decision: "ddeny",
      reason: "system-path permission mutation is denied",
      matchedRuleId: "exec.pattern.system-permission-mutation",
    };
  }
  return null;
}

function determineConfirmationRequirement(request, finalRiskLevel, flags, objectRisk, policy) {
  const base = path.posix.basename(trimText(request?.scope?.exec?.command) || "");
  if (
    finalRiskLevel === "L3" &&
    !flags.effectFlags.destructive &&
    objectRisk.classification !== "critical" &&
    (ARCHIVE_COMMANDS.includes(base) ||
      (policy.exec.confirmableCommands.includes(base) && flags.effectFlags.export))
  ) {
    return {
      reason: "trusted user confirmation required for high-impact export or archival effect",
      matchedRuleId: "exec.confirm.high-impact-export",
      executionMode: "ree-constrained",
    };
  }
  return null;
}

function selectDominantAssessment(level, assessments) {
  return (
    assessments.find((assessment) => assessment.level === level) ?? {
      level,
      reason: "aggregated trusted risk assessment",
      matchedRuleId: "risk.aggregate",
    }
  );
}

export function evaluateTrustedAuthorizeRequest(request, policy) {
  const actionRisk = classifyActionRisk(request, policy);
  const objectRisk = classifyObjectRisk(request, policy);
  const contextRisk = classifyContextRisk(request, policy, objectRisk);
  const effectRisk = classifyEffectRisk(request, actionRisk, objectRisk, contextRisk);
  const flags = flagsFromAssessment(objectRisk, contextRisk, effectRisk);
  const patternMatch = matchPatternRule(request, flags);
  const finalRiskLevel = maxRisk(
    actionRisk.level,
    objectRisk.level,
    contextRisk.level,
    effectRisk.level,
    patternMatch?.level ?? "L0",
  );
  const confirmationRequirement = determineConfirmationRequirement(
    request,
    finalRiskLevel,
    flags,
    objectRisk,
    policy,
  );
  const dominantAssessment = selectDominantAssessment(finalRiskLevel, [
    effectRisk,
    contextRisk,
    objectRisk,
    actionRisk,
  ]);

  let finalDecision;
  let executionMode;
  let finalReason;
  let matchedRuleId;
  if (patternMatch) {
    finalDecision = patternMatch.decision;
    executionMode =
      patternMatch.decision === "ddeny"
        ? finalRiskLevel === "L0"
          ? "ree-direct"
          : finalRiskLevel === "L1"
            ? "ree-constrained"
            : "isolated"
        : executionModeForDecision(patternMatch.decision);
    finalReason = patternMatch.reason;
    matchedRuleId = patternMatch.matchedRuleId;
  } else if (confirmationRequirement) {
    finalDecision = "duc";
    executionMode = confirmationRequirement.executionMode;
    finalReason = confirmationRequirement.reason;
    matchedRuleId = confirmationRequirement.matchedRuleId;
  } else {
    finalDecision =
      finalRiskLevel === "L0"
        ? "dree"
        : finalRiskLevel === "L1"
          ? "dia"
          : finalRiskLevel === "L2"
            ? "die"
            : (policy.exec.decisionMap.L3 ?? "ddeny");
    executionMode =
      finalDecision === "ddeny"
        ? finalRiskLevel === "L0"
          ? "ree-direct"
          : finalRiskLevel === "L1"
            ? "ree-constrained"
            : "isolated"
        : executionModeForDecision(finalDecision);
    finalReason = dominantAssessment.reason;
    matchedRuleId = dominantAssessment.matchedRuleId;
  }

  const normalizedRequest = normalizeRequestLevel(request, finalRiskLevel);
  return {
    allow: finalDecision === "dree" || finalDecision === "dia" || finalDecision === "die",
    decision: finalDecision,
    level: finalRiskLevel,
    executionMode,
    reason: finalReason,
    matchedRuleId,
    normalizedRequest,
    classification: {
      actionRisk,
      objectRisk,
      contextRisk,
      effectRisk,
      contextFlags: flags.contextFlags,
      effectFlags: flags.effectFlags,
      finalRiskLevel,
      decision: finalDecision,
      reason: finalReason,
      matchedRuleId,
    },
  };
}
