import { describe, expect, it } from "vitest";
import {
  DEFAULT_TRUSTED_POLICY,
  evaluateTrustedAuthorizeRequest,
} from "../../external/openclaw-trusted-backend/policy.mjs";

type ExecRequestOverrides = {
  rawCommand: string;
  command: string;
  args: string[];
  matchMode?: "exact" | "shell-exact";
  cwd?: string;
  workspaceRoot?: string;
};

function buildExecRequest(overrides: ExecRequestOverrides) {
  const workspaceRoot = overrides.workspaceRoot ?? "/home/zqw/openclaw";
  const cwd = overrides.cwd ?? workspaceRoot;
  return {
    version: 1,
    reqId: "req-1",
    sid: "sid-1",
    seq: 1,
    ttlMs: 5_000,
    issuedAtMs: 1_775_021_039_253,
    toolName: "exec",
    action: "exec",
    object: overrides.rawCommand,
    scope: {
      action: "exec",
      target: overrides.rawCommand,
      exec: {
        matchMode: overrides.matchMode ?? "exact",
        rawCommand: overrides.rawCommand,
        command: overrides.command,
        args: overrides.args,
        cwd,
      },
      restrictions: {},
    },
    context: {
      agentId: "ti-agent",
      runId: "policy-test",
      toolCallId: "tc-policy",
      sessionKey: "trusted-session-1",
      workdir: cwd,
      workspaceRoot,
    },
    level: "L1",
    normalizedScopeDigest: "scope-digest",
    requestDigest: "request-digest",
  };
}

describe("trusted backend policy", () => {
  it("keeps literal echo operands out of object-risk escalation", () => {
    const evaluation = evaluateTrustedAuthorizeRequest(
      buildExecRequest({
        rawCommand: "echo wa-trusted",
        command: "echo",
        args: ["wa-trusted"],
      }),
      DEFAULT_TRUSTED_POLICY,
    );

    expect(evaluation.level).toBe("L1");
    expect(evaluation.decision).toBe("dia");
    expect(evaluation.executionMode).toBe("ree-constrained");
    expect(evaluation.classification.objectRisk).toMatchObject({
      level: "L0",
      classification: "ordinary",
      matchedRuleId: "object.ordinary.workspace",
    });
  });

  it("treats workspace-local file operands as ordinary objects", () => {
    const evaluation = evaluateTrustedAuthorizeRequest(
      buildExecRequest({
        rawCommand: "cat README.md",
        command: "cat",
        args: ["README.md"],
      }),
      DEFAULT_TRUSTED_POLICY,
    );

    expect(evaluation.level).toBe("L1");
    expect(evaluation.decision).toBe("dia");
    expect(evaluation.classification.objectRisk).toMatchObject({
      level: "L0",
      classification: "ordinary",
      matchedRuleId: "object.ordinary.workspace",
    });
  });

  it("skips grep pattern operands and classifies only the file target", () => {
    const evaluation = evaluateTrustedAuthorizeRequest(
      buildExecRequest({
        rawCommand: "grep TODO README.md",
        command: "grep",
        args: ["TODO", "README.md"],
      }),
      DEFAULT_TRUSTED_POLICY,
    );

    expect(evaluation.level).toBe("L1");
    expect(evaluation.decision).toBe("dia");
    expect(evaluation.classification.objectRisk.matchedRuleId).toBe("object.ordinary.workspace");
  });

  it("still tracks redirection targets for printf", () => {
    const evaluation = evaluateTrustedAuthorizeRequest(
      buildExecRequest({
        rawCommand: "printf trusted-hi > trusted.txt",
        command: "printf",
        args: ["trusted-hi", ">", "trusted.txt"],
      }),
      DEFAULT_TRUSTED_POLICY,
    );

    expect(evaluation.level).toBe("L1");
    expect(evaluation.decision).toBe("dia");
    expect(evaluation.classification.objectRisk).toMatchObject({
      level: "L0",
      classification: "ordinary",
    });
  });

  it("still escalates protected path access to denial", () => {
    const evaluation = evaluateTrustedAuthorizeRequest(
      buildExecRequest({
        rawCommand: "cat ~/.ssh/id_rsa",
        command: "cat",
        args: ["~/.ssh/id_rsa"],
      }),
      DEFAULT_TRUSTED_POLICY,
    );

    expect(evaluation.level).toBe("L3");
    expect(evaluation.decision).toBe("ddeny");
    expect(evaluation.classification.objectRisk).toMatchObject({
      level: "L3",
      classification: "critical",
      matchedRuleId: "object.critical.protected-path",
    });
  });

  it("classifies shell compound commands without phantom path targets", () => {
    const evaluation = evaluateTrustedAuthorizeRequest(
      buildExecRequest({
        rawCommand:
          "if [ -f HEARTBEAT.md ]; then sed -n '1,240p' HEARTBEAT.md; else echo '__NO_HEARTBEAT__'; fi",
        command: "shell-compound",
        args: [],
        matchMode: "shell-exact",
      }),
      DEFAULT_TRUSTED_POLICY,
    );

    expect(evaluation.level).toBe("L2");
    expect(evaluation.decision).toBe("die");
    expect(evaluation.executionMode).toBe("isolated");
    expect(evaluation.classification.actionRisk).toMatchObject({
      level: "L2",
      matchedRuleId: "exec.action.shell-compound",
    });
    expect(evaluation.classification.contextRisk).toMatchObject({
      level: "L2",
      matchedRuleId: "context.multi-step",
    });
    expect(evaluation.classification.objectRisk).toMatchObject({
      level: "L0",
      classification: "ordinary",
      matchedRuleId: "object.ordinary.workspace",
    });
  });

  it("routes archive packaging through duc with graded effect risk", () => {
    const evaluation = evaluateTrustedAuthorizeRequest(
      buildExecRequest({
        rawCommand: "tar -czf workspace.tgz docs",
        command: "tar",
        args: ["-czf", "workspace.tgz", "docs"],
      }),
      DEFAULT_TRUSTED_POLICY,
    );

    expect(evaluation.level).toBe("L3");
    expect(evaluation.decision).toBe("duc");
    expect(evaluation.executionMode).toBe("ree-constrained");
    expect(evaluation.classification.effectRisk).toMatchObject({
      level: "L3",
      matchedRuleId: "effect.export-or-archive",
    });
    expect(evaluation.classification.contextRisk).toMatchObject({
      level: "L1",
      matchedRuleId: "context.reduced-operator",
    });
  });
});
