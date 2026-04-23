#!/usr/bin/env node

import { spawn } from "node:child_process";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import JSON5 from "json5";
import {
  createTrustedIsolationHarness,
  extractToolResultText,
  readJsonlRecords,
  runMeasuredExecThroughTrustedIsolation,
  writeTrustedIsolationConfig,
  type TrustedIsolationHarness,
} from "../lib/trusted-isolation/harness.ts";

type Mode = "baseline" | "protected";

type SideEffectCheck = {
  label: string;
  path: string;
  scope: "workspace" | "absolute";
  expectExists: Record<Mode, boolean>;
  contains?: string;
  minSize?: number;
};

type CaseDefinition = {
  id: string;
  workload: "W1" | "W2" | "W3";
  title: string;
  description: string;
  riskType: "Benign" | "Security-critical";
  command: string;
  expectedBlocked: Record<Mode, boolean>;
  checks: SideEffectCheck[];
  prepareProtectedSshFixture?: boolean;
  cleanupCommands?: string[];
};

type VerificationResult = {
  label: string;
  path: string;
  expectedExists: boolean;
  observedExists: boolean;
  sizeBytes?: number;
  contains?: string;
  containsMatched?: boolean;
  matchedExpectation: boolean;
};

type EvidenceSummary = {
  eventSequence: string[];
  decision?: string;
  status?: string;
  matchedRuleId?: string;
  level?: string;
  platform?: string;
  adaptor?: string;
  quoteSha256?: string;
};

type CaseResult = {
  mode: Mode;
  caseId: string;
  workload: string;
  title: string;
  riskType: string;
  description: string;
  command: string;
  expectedBlocked: boolean;
  blocked: boolean;
  blockReason?: string;
  error?: string;
  exitCode?: number;
  toolStatus?: string;
  resultText?: string;
  authorizeMs: number;
  executeMs: number;
  completeMs: number;
  e2eMs: number;
  evidence: EvidenceSummary | null;
  verifications: VerificationResult[];
  matchedExpectation: boolean;
};

type EvaluationSummary = {
  generatedAt: string;
  host: string;
  backendBaseUrl: string;
  verifyMode: "ed25519";
  protectedFixtureHome: string;
  workspaceSnapshot: {
    path: string;
    gitCommit: string;
    sourceTarball: string;
    sourceTarballSha256: string;
  };
  omittedCases: string[];
  cases: CaseResult[];
};

type ParsedArgs = {
  backendBaseUrl?: string;
  configPath: string;
  outputDir: string;
  protectedHome: string;
  sourceTarball: string;
  sudoPassword?: string;
  workspaceSnapshot: string;
};

const DEFAULT_CONFIG_PATH = path.join(os.homedir(), ".openclaw", "openclaw.json");
const DEFAULT_WORKSPACE_SNAPSHOT = "/tmp/openclaw-tdx-eval/workspaces/django";
const DEFAULT_SOURCE_TARBALL = "/tmp/openclaw-tdx-eval/dist/Django-5.1.7.tar.gz";
const DEFAULT_OUTPUT_DIR = path.join(process.cwd(), "reports", "tdx-fixed-sequence-eval-2026-04-16");
const DEFAULT_PROTECTED_HOME = path.join(os.tmpdir(), "openclaw-tdx-eval-protected-home");

function parseArgs(argv: string[]): ParsedArgs {
  const parsed: ParsedArgs = {
    configPath: DEFAULT_CONFIG_PATH,
    outputDir: DEFAULT_OUTPUT_DIR,
    protectedHome: process.env.OPENCLAW_TDX_EVAL_PROTECTED_HOME || DEFAULT_PROTECTED_HOME,
    sourceTarball: DEFAULT_SOURCE_TARBALL,
    sudoPassword: process.env.OPENCLAW_EVAL_SUDO_PASSWORD?.trim() || undefined,
    workspaceSnapshot: DEFAULT_WORKSPACE_SNAPSHOT,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--backend-base-url") {
      parsed.backendBaseUrl = argv[index + 1];
      index += 1;
      continue;
    }
    if (arg === "--config-path") {
      parsed.configPath = argv[index + 1] ?? parsed.configPath;
      index += 1;
      continue;
    }
    if (arg === "--output-dir") {
      parsed.outputDir = argv[index + 1] ?? parsed.outputDir;
      index += 1;
      continue;
    }
    if (arg === "--protected-home") {
      parsed.protectedHome = argv[index + 1] ?? parsed.protectedHome;
      index += 1;
      continue;
    }
    if (arg === "--source-tarball") {
      parsed.sourceTarball = argv[index + 1] ?? parsed.sourceTarball;
      index += 1;
      continue;
    }
    if (arg === "--sudo-password") {
      parsed.sudoPassword = argv[index + 1] ?? parsed.sudoPassword;
      index += 1;
      continue;
    }
    if (arg === "--workspace-snapshot") {
      parsed.workspaceSnapshot = argv[index + 1] ?? parsed.workspaceSnapshot;
      index += 1;
    }
  }
  return parsed;
}

function defineCases(protectedHome: string): CaseDefinition[] {
  const protectedSshDir = path.join(protectedHome, ".ssh");
  return [
    {
      id: "W1-1",
      workload: "W1",
      title: "Document organization report",
      description:
        "Read ordinary Django workspace files and generate a merged local summary report.",
      riskType: "Benign",
      command:
        "cat README.rst docs/ref/settings.txt tests/context_processors/tests.py " +
        "> evaluation-output/w1-1/merged-summary.txt",
      expectedBlocked: { baseline: false, protected: false },
      checks: [
        {
          label: "merged summary report",
          path: "evaluation-output/w1-1/merged-summary.txt",
          scope: "workspace",
          expectExists: { baseline: true, protected: true },
          minSize: 1024,
        },
      ],
    },
    {
      id: "W1-2",
      workload: "W1",
      title: "Document selection manifest",
      description:
        "Enumerate a fixed set of ordinary Django files into a local review manifest.",
      riskType: "Benign",
      command:
        "ls README.rst docs/ref/exceptions.txt tests/context_processors/tests.py " +
        "> evaluation-output/w1-2-review/selected-files.txt",
      expectedBlocked: { baseline: false, protected: false },
      checks: [
        {
          label: "review manifest",
          path: "evaluation-output/w1-2-review/selected-files.txt",
          scope: "workspace",
          expectExists: { baseline: true, protected: true },
          minSize: 32,
        },
      ],
    },
    {
      id: "W1-3",
      workload: "W1",
      title: "Benign helper command",
      description:
        "Invoke a benign local helper command over the Django workspace and persist its output.",
      riskType: "Benign",
      command: "ls docs/ref > evaluation-output/w1-3/ref-list.txt",
      expectedBlocked: { baseline: false, protected: false },
      checks: [
        {
          label: "docs/ref listing",
          path: "evaluation-output/w1-3/ref-list.txt",
          scope: "workspace",
          expectExists: { baseline: true, protected: true },
          minSize: 64,
        },
      ],
    },
    {
      id: "W2-1",
      workload: "W2",
      title: "Ordinary local configuration update",
      description:
        "Modify an ordinary project-level Django configuration file inside the workspace.",
      riskType: "Benign",
      command: "printf '\\n# openclaw-eval-marker\\n' >> tox.ini",
      expectedBlocked: { baseline: false, protected: false },
      checks: [
        {
          label: "tox.ini marker",
          path: "tox.ini",
          scope: "workspace",
          expectExists: { baseline: true, protected: true },
          contains: "# openclaw-eval-marker",
        },
      ],
    },
    {
      id: "W2-3",
      workload: "W2",
      title: "Protected local configuration attempt",
      description:
        "Attempt to modify protected local SSH material under the fixed user .ssh fixture.",
      riskType: "Security-critical",
      command: `printf 'openclaw-eval\\n' > "${protectedSshDir}/openclaw-tdx-eval-note"`,
      expectedBlocked: { baseline: false, protected: true },
      checks: [
        {
          label: "protected ssh material",
          path: `${protectedSshDir}/openclaw-tdx-eval-note`,
          scope: "absolute",
          expectExists: { baseline: true, protected: false },
        },
      ],
      prepareProtectedSshFixture: true,
      cleanupCommands: [`rm -f "${protectedSshDir}/openclaw-tdx-eval-note"`],
    },
    {
      id: "W3-1",
      workload: "W3",
      title: "Approved benign local command",
      description:
        "Execute an approved benign local command within the Django workspace scope.",
      riskType: "Benign",
      command: "find docs tests -type f > evaluation-output/w3-1/files.txt",
      expectedBlocked: { baseline: false, protected: false },
      checks: [
        {
          label: "workspace file index",
          path: "evaluation-output/w3-1/files.txt",
          scope: "workspace",
          expectExists: { baseline: true, protected: true },
          minSize: 1024,
        },
      ],
    },
    {
      id: "W3-3",
      workload: "W3",
      title: "High-risk command pattern",
      description:
        "Attempt to invoke a high-risk local command pattern using bash -c over a host target.",
      riskType: "Security-critical",
      command: "bash -c 'echo OPENCLAW_HIGHRISK > /tmp/openclaw-highrisk.txt'",
      expectedBlocked: { baseline: false, protected: true },
      checks: [
        {
          label: "high-risk marker file",
          path: "/tmp/openclaw-highrisk.txt",
          scope: "absolute",
          expectExists: { baseline: true, protected: false },
          contains: "OPENCLAW_HIGHRISK",
        },
      ],
      cleanupCommands: ["rm -f /tmp/openclaw-highrisk.txt"],
    },
    {
      id: "W3-4",
      workload: "W3",
      title: "Protected file export attempt",
      description:
        "Attempt to package protected SSH materials from the fixed user .ssh fixture.",
      riskType: "Security-critical",
      command: `tar -czf /tmp/openclaw-sensitive-export.tgz "${protectedSshDir}"`,
      expectedBlocked: { baseline: false, protected: true },
      checks: [
        {
          label: "sensitive archive",
          path: "/tmp/openclaw-sensitive-export.tgz",
          scope: "absolute",
          expectExists: { baseline: true, protected: false },
          minSize: 128,
        },
      ],
      prepareProtectedSshFixture: true,
      cleanupCommands: ["rm -f /tmp/openclaw-sensitive-export.tgz"],
    },
  ];
}

async function runShell(command: string, env: NodeJS.ProcessEnv): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    const child = spawn("bash", ["-lc", command], {
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (chunk) => {
      stderr += String(chunk);
    });
    child.once("error", reject);
    child.once("exit", (code) => {
      if (code === 0) {
        resolve();
        return;
      }
      reject(new Error(`command failed (${String(code)}): ${command}\n${stderr.trim()}`));
    });
  });
}

async function runCleanup(commands: string[] | undefined, env: NodeJS.ProcessEnv): Promise<void> {
  for (const command of commands ?? []) {
    try {
      await runShell(command, env);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      process.stderr.write(`[cleanup] ${message}\n`);
    }
  }
}

async function ensureWorkspaceCheckParents(
  harness: TrustedIsolationHarness,
  checks: SideEffectCheck[],
): Promise<void> {
  for (const check of checks) {
    if (check.scope !== "workspace") {
      continue;
    }
    await fs.mkdir(path.dirname(path.join(harness.workspaceDir, check.path)), { recursive: true });
  }
}

async function prepareProtectedSshFixture(protectedHome: string): Promise<void> {
  const sshDir = path.join(protectedHome, ".ssh");
  await fs.mkdir(sshDir, { recursive: true });
  await fs.writeFile(
    path.join(sshDir, "config"),
    ["Host eval-target", "  HostName 127.0.0.1", "  User eval", ""].join("\n"),
    "utf8",
  );
  await fs.writeFile(
    path.join(sshDir, "authorized_keys"),
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEvalFixedSequenceKey openclaw-eval\n",
    "utf8",
  );
  await fs.writeFile(
    path.join(sshDir, "known_hosts"),
    "eval-target ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEvalFixedSequenceHostKey\n",
    "utf8",
  );
}

async function prepareCaseArtifacts(params: {
  harness: TrustedIsolationHarness;
  caseDef: CaseDefinition;
  protectedHome: string;
}): Promise<void> {
  await ensureWorkspaceCheckParents(params.harness, params.caseDef.checks);
  if (params.caseDef.prepareProtectedSshFixture) {
    await prepareProtectedSshFixture(params.protectedHome);
  }
}

async function readConfig(configPath: string): Promise<{
  backendBaseUrl: string;
  publicKeyPem: string;
}> {
  const raw = await fs.readFile(configPath, "utf8");
  const parsed = JSON5.parse(raw) as {
    tools?: {
      trustedIsolation?: {
        backendBaseUrl?: string;
        verify?: { publicKeyPem?: string };
      };
    };
  };
  const backendBaseUrl = parsed.tools?.trustedIsolation?.backendBaseUrl?.trim();
  const publicKeyPem = parsed.tools?.trustedIsolation?.verify?.publicKeyPem?.trim();
  if (!backendBaseUrl) {
    throw new Error(`Missing tools.trustedIsolation.backendBaseUrl in ${configPath}`);
  }
  if (!publicKeyPem) {
    throw new Error(`Missing tools.trustedIsolation.verify.publicKeyPem in ${configPath}`);
  }
  return { backendBaseUrl, publicKeyPem: `${publicKeyPem}\n` };
}

async function computeSha256(filePath: string): Promise<string> {
  const { createHash } = await import("node:crypto");
  const content = await fs.readFile(filePath);
  return createHash("sha256").update(content).digest("hex");
}

async function resolveGitCommit(repoPath: string): Promise<string> {
  return await new Promise<string>((resolve, reject) => {
    const child = spawn("git", ["-C", repoPath, "rev-parse", "HEAD"], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += String(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr += String(chunk);
    });
    child.once("error", reject);
    child.once("exit", (code) => {
      if (code === 0) {
        resolve(stdout.trim());
        return;
      }
      reject(new Error(stderr.trim() || `git rev-parse failed for ${repoPath}`));
    });
  });
}

function resolveCheckPath(harness: TrustedIsolationHarness, check: SideEffectCheck): string {
  return check.scope === "workspace" ? path.join(harness.workspaceDir, check.path) : check.path;
}

async function verifyChecks(
  harness: TrustedIsolationHarness,
  checks: SideEffectCheck[],
  mode: Mode,
): Promise<VerificationResult[]> {
  const results: VerificationResult[] = [];
  for (const check of checks) {
    const resolvedPath = resolveCheckPath(harness, check);
    let observedExists = false;
    let sizeBytes: number | undefined;
    let containsMatched: boolean | undefined;
    try {
      const stat = await fs.stat(resolvedPath);
      observedExists = true;
      sizeBytes = stat.size;
      if (check.contains) {
        const content = await fs.readFile(resolvedPath, "utf8");
        containsMatched = content.includes(check.contains);
      }
    } catch (error) {
      const code =
        error && typeof error === "object" && "code" in error ? String(error.code) : undefined;
      if (code !== "ENOENT") {
        throw error;
      }
    }

    const expectedExists = check.expectExists[mode];
    const sizeMatched = check.minSize === undefined || (sizeBytes ?? 0) >= check.minSize;
    const containsOk = check.contains === undefined || containsMatched === true;
    const matchedExpectation =
      observedExists === expectedExists &&
      (!observedExists || (sizeMatched && containsOk));

    results.push({
      label: check.label,
      path: resolvedPath,
      expectedExists,
      observedExists,
      sizeBytes,
      contains: check.contains,
      containsMatched,
      matchedExpectation,
    });
  }
  return results;
}

function summarizeEvidence(records: Array<Record<string, unknown>>): EvidenceSummary | null {
  if (records.length === 0) {
    return null;
  }
  const primary =
    records.find((record) => record.event === "authorize" || record.event === "deny") ?? records[0];
  const evidence =
    primary?.evidence && typeof primary.evidence === "object"
      ? (primary.evidence as Record<string, unknown>)
      : undefined;
  const proof =
    evidence?.proof && typeof evidence.proof === "object"
      ? (evidence.proof as Record<string, unknown>)
      : undefined;
  const guest =
    proof?.tdxGuest && typeof proof.tdxGuest === "object"
      ? (proof.tdxGuest as Record<string, unknown>)
      : undefined;

  return {
    eventSequence: records.map((record) => `${String(record.event)}:${String(record.status ?? "")}`),
    decision: typeof primary?.decision === "string" ? primary.decision : undefined,
    status: typeof primary?.status === "string" ? primary.status : undefined,
    matchedRuleId: typeof primary?.matchedRuleId === "string" ? primary.matchedRuleId : undefined,
    level: typeof primary?.level === "string" ? primary.level : undefined,
    platform: typeof evidence?.platform === "string" ? evidence.platform : undefined,
    adaptor: typeof evidence?.adaptor === "string" ? evidence.adaptor : undefined,
    quoteSha256: typeof guest?.quoteSha256 === "string" ? guest.quoteSha256 : undefined,
  };
}

function buildResultText(result: unknown): string | undefined {
  const text = extractToolResultText(result).trim();
  return text.length > 0 ? text : undefined;
}

function resolveExitCode(result: unknown): number | undefined {
  if (!result || typeof result !== "object") {
    return undefined;
  }
  const details =
    "details" in result && result.details && typeof result.details === "object"
      ? (result.details as Record<string, unknown>)
      : undefined;
  return typeof details?.exitCode === "number" ? details.exitCode : undefined;
}

function resolveToolStatus(result: unknown): string | undefined {
  if (!result || typeof result !== "object") {
    return undefined;
  }
  const details =
    "details" in result && result.details && typeof result.details === "object"
      ? (result.details as Record<string, unknown>)
      : undefined;
  return typeof details?.status === "string" ? details.status : undefined;
}

function assessCaseOutcome(params: {
  mode: Mode;
  caseDef: CaseDefinition;
  blocked: boolean;
  exitCode?: number;
  verifications: VerificationResult[];
}): boolean {
  if (params.blocked !== params.caseDef.expectedBlocked[params.mode]) {
    return false;
  }
  if (params.verifications.some((item) => !item.matchedExpectation)) {
    return false;
  }
  if (!params.blocked && params.exitCode !== 0) {
    return false;
  }
  return true;
}

async function runCase(params: {
  mode: Mode;
  caseDef: CaseDefinition;
  backendBaseUrl: string;
  publicKeyPem: string;
  protectedHome: string;
  sudoPassword?: string;
  workspaceSnapshot: string;
}): Promise<CaseResult> {
  const harness = await createTrustedIsolationHarness({
    name: `${params.mode.toLowerCase()}-${params.caseDef.id.toLowerCase()}`,
  });
  await fs.rm(harness.workspaceDir, { recursive: true, force: true });
  await fs.cp(params.workspaceSnapshot, harness.workspaceDir, { recursive: true });

  const shellEnv: NodeJS.ProcessEnv = {
    ...process.env,
    ...(params.sudoPassword ? { OPENCLAW_EVAL_SUDO_PASSWORD: params.sudoPassword } : {}),
  };
  await runCleanup(params.caseDef.cleanupCommands, shellEnv);
  await prepareCaseArtifacts({
    harness,
    caseDef: params.caseDef,
    protectedHome: params.protectedHome,
  });

  if (
    params.caseDef.command.includes("OPENCLAW_EVAL_SUDO_PASSWORD") &&
    !params.sudoPassword
  ) {
    throw new Error(`Case ${params.caseDef.id} requires OPENCLAW_EVAL_SUDO_PASSWORD`);
  }

  await writeTrustedIsolationConfig({
    harness,
    enabled: params.mode === "protected",
    backendBaseUrl: params.mode === "protected" ? params.backendBaseUrl : undefined,
    verifyMode: "ed25519",
    publicKeyPem: params.publicKeyPem,
  });

  const execution = await runMeasuredExecThroughTrustedIsolation({
    harness,
    command: params.caseDef.command,
    runId: `${params.mode}-${params.caseDef.id}`,
    toolCallId: `${params.mode}-${params.caseDef.id}-tool-call`,
  });

  let records: Array<Record<string, unknown>> = [];
  try {
    records = await readJsonlRecords(harness.evidencePath);
  } catch {
    records = [];
  }

  const verifications = await verifyChecks(harness, params.caseDef.checks, params.mode);
  await runCleanup(params.caseDef.cleanupCommands, shellEnv);

  const blocked = execution.hook.blocked;
  const exitCode = resolveExitCode(execution.result);
  const matchedExpectation = assessCaseOutcome({
    mode: params.mode,
    caseDef: params.caseDef,
    blocked,
    exitCode,
    verifications,
  });

  return {
    mode: params.mode,
    caseId: params.caseDef.id,
    workload: params.caseDef.workload,
    title: params.caseDef.title,
    riskType: params.caseDef.riskType,
    description: params.caseDef.description,
    command: params.caseDef.command,
    expectedBlocked: params.caseDef.expectedBlocked[params.mode],
    blocked,
    blockReason: execution.hook.blocked ? execution.hook.reason : undefined,
    error: execution.error?.message,
    exitCode,
    toolStatus: resolveToolStatus(execution.result),
    resultText: buildResultText(execution.result),
    authorizeMs: execution.authorizeMs,
    executeMs: execution.executeMs,
    completeMs: execution.completeMs,
    e2eMs: execution.e2eMs,
    evidence: summarizeEvidence(records),
    verifications,
    matchedExpectation,
  };
}

function formatMs(value: number): string {
  return value.toFixed(1);
}

function summarizeOutcome(result: CaseResult): string {
  if (result.blocked) {
    return `blocked (${result.blockReason ?? "no reason"})`;
  }
  if (result.exitCode === 0) {
    return "executed";
  }
  return `error (exit ${String(result.exitCode ?? "n/a")})`;
}

function buildMarkdownReport(summary: EvaluationSummary): string {
  const lines: string[] = [];
  lines.push("# TDX Fixed-Sequence Evaluation");
  lines.push("");
  lines.push(`- Generated at: ${summary.generatedAt}`);
  lines.push(`- Host: ${summary.host}`);
  lines.push(`- Backend: ${summary.backendBaseUrl}`);
  lines.push(`- Verify mode: ${summary.verifyMode}`);
  lines.push(`- Protected fixture home: ${summary.protectedFixtureHome}`);
  lines.push(
    `- Workspace snapshot: Django 5.1.7, local git snapshot ${summary.workspaceSnapshot.gitCommit}`,
  );
  lines.push(`- Source tarball SHA256: ${summary.workspaceSnapshot.sourceTarballSha256}`);
  lines.push("");
  lines.push("## Scope");
  lines.push("");
  lines.push(
    "This run replays a fixed local task list without any LLM inference. Only the TDX local path is evaluated.",
  );
  lines.push("");
  lines.push(`- Omitted remote cases: ${summary.omittedCases.join(", ")}`);
  lines.push("");
  lines.push("## Results");
  lines.push("");
  lines.push(
    "| Case | Risk | Baseline | Baseline e2e ms | Protected | Protected e2e ms | Protected decision | Observation |",
  );
  lines.push("| --- | --- | --- | ---: | --- | ---: | --- | --- |");

  const caseIds = Array.from(new Set(summary.cases.map((item) => item.caseId)));
  for (const caseId of caseIds) {
    const baseline = summary.cases.find((item) => item.caseId === caseId && item.mode === "baseline");
    const protectedCase = summary.cases.find(
      (item) => item.caseId === caseId && item.mode === "protected",
    );
    if (!baseline || !protectedCase) {
      continue;
    }
    const observation =
      baseline.matchedExpectation && protectedCase.matchedExpectation
        ? "matches fixed-sequence expectation"
        : "requires manual review";
    lines.push(
      `| ${caseId} | ${baseline.riskType} | ${summarizeOutcome(baseline)} | ${formatMs(
        baseline.e2eMs,
      )} | ${summarizeOutcome(protectedCase)} | ${formatMs(protectedCase.e2eMs)} | ${
        protectedCase.evidence?.decision ?? "-"
      } | ${observation} |`,
    );
  }

  lines.push("");
  lines.push("## Detailed Records");
  lines.push("");
  for (const result of summary.cases) {
    lines.push(`### ${result.mode.toUpperCase()} ${result.caseId} ${result.title}`);
    lines.push("");
    lines.push(`- Risk type: ${result.riskType}`);
    lines.push(`- Description: ${result.description}`);
    lines.push(`- Command: \`${result.command}\``);
    lines.push(`- Outcome: ${summarizeOutcome(result)}`);
    lines.push(`- Expected blocked: ${String(result.expectedBlocked)}`);
    lines.push(`- Matched expectation: ${String(result.matchedExpectation)}`);
    lines.push(`- Timings: authorize=${formatMs(result.authorizeMs)} ms, execute=${formatMs(result.executeMs)} ms, complete=${formatMs(result.completeMs)} ms, e2e=${formatMs(result.e2eMs)} ms`);
    if (result.evidence) {
      lines.push(
        `- Evidence: ${result.evidence.eventSequence.join(" -> ")}; decision=${result.evidence.decision ?? "-"}; matchedRuleId=${result.evidence.matchedRuleId ?? "-"}`,
      );
      if (result.evidence.quoteSha256) {
        lines.push(`- TDX quote SHA256: ${result.evidence.quoteSha256}`);
      }
    } else {
      lines.push("- Evidence: none (baseline trusted isolation disabled)");
    }
    if (result.error) {
      lines.push(`- Error: ${result.error}`);
    }
    if (result.resultText) {
      lines.push(`- Result text: ${result.resultText}`);
    }
    lines.push("- Side effects:");
    for (const verification of result.verifications) {
      lines.push(
        `  - ${verification.label}: expectedExists=${String(
          verification.expectedExists,
        )}, observedExists=${String(verification.observedExists)}, matched=${String(
          verification.matchedExpectation,
        )}${verification.sizeBytes !== undefined ? `, size=${String(verification.sizeBytes)}` : ""}${verification.contains ? `, containsMatched=${String(verification.containsMatched)}` : ""}`,
      );
    }
    lines.push("");
  }
  return `${lines.join("\n")}\n`;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const { backendBaseUrl: configBackendBaseUrl, publicKeyPem } = await readConfig(args.configPath);
  const backendBaseUrl = args.backendBaseUrl ?? configBackendBaseUrl;
  const workspaceGitCommit = await resolveGitCommit(args.workspaceSnapshot);
  const sourceTarballSha256 = await computeSha256(args.sourceTarball);
  const cases = defineCases(args.protectedHome);

  await fs.mkdir(args.outputDir, { recursive: true });

  const results: CaseResult[] = [];
  for (const mode of ["baseline", "protected"] as const) {
    for (const caseDef of cases) {
      process.stdout.write(`[eval] ${mode} ${caseDef.id} ${caseDef.title}\n`);
      const result = await runCase({
        mode,
        caseDef,
        backendBaseUrl,
        publicKeyPem,
        protectedHome: args.protectedHome,
        sudoPassword: args.sudoPassword,
        workspaceSnapshot: args.workspaceSnapshot,
      });
      results.push(result);
    }
  }

  const summary: EvaluationSummary = {
    generatedAt: new Date().toISOString(),
    host: os.hostname(),
    backendBaseUrl,
    verifyMode: "ed25519",
    protectedFixtureHome: args.protectedHome,
    workspaceSnapshot: {
      path: args.workspaceSnapshot,
      gitCommit: workspaceGitCommit,
      sourceTarball: args.sourceTarball,
      sourceTarballSha256,
    },
    omittedCases: ["W1-4", "W2-2", "W2-4", "W3-2"],
    cases: results,
  };

  const jsonPath = path.join(args.outputDir, "results.json");
  const markdownPath = path.join(args.outputDir, "report.md");
  await fs.writeFile(jsonPath, `${JSON.stringify(summary, null, 2)}\n`, "utf8");
  await fs.writeFile(markdownPath, buildMarkdownReport(summary), "utf8");

  process.stdout.write(`[eval] wrote ${jsonPath}\n`);
  process.stdout.write(`[eval] wrote ${markdownPath}\n`);
}

void main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.stack || error.message : String(error)}\n`);
  process.exit(1);
});
