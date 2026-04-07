import fs from "node:fs/promises";
import path from "node:path";
import type { AgentTool } from "@mariozechner/pi-agent-core";
import { Type } from "@sinclair/typebox";
import { removePathWithinRoot } from "../infra/fs-safe.js";
import { PATH_ALIAS_POLICIES } from "../infra/path-alias-guards.js";
import { resolveTrustedIsolationConfig } from "../security/trusted-isolation/config.js";
import { enforceTrustedScopeForPath } from "../security/trusted-isolation/scope.js";
import { resolvePathFromInput } from "./path-policy.js";
import {
  CLAUDE_PARAM_GROUPS,
  normalizeToolParams,
  wrapToolParamNormalization,
} from "./pi-tools.params.js";
import type { AnyAgentTool } from "./pi-tools.types.js";
import { assertSandboxPath } from "./sandbox-paths.js";
import type { SandboxFsBridge } from "./sandbox/fs-bridge.js";
import { textResult, ToolInputError } from "./tools/common.js";

type SandboxToolParams = {
  root: string;
  bridge: SandboxFsBridge;
};

type DeleteToolOptions = {
  workspaceOnly?: boolean;
};

type DeleteToolDetails = {
  status: "completed";
  deletedPath: string;
};

const DELETE_TOOL_DESCRIPTION =
  "Delete a single file from the current workspace. Prefer this over exec commands like rm or unlink when the user explicitly asked to remove one file. This tool does not support directories, recursive deletion, or multiple targets.";

const deleteToolSchema = Type.Object({
  path: Type.String({
    description:
      "Single file path to delete from the current workspace. Use only when the user explicitly asked to remove that file.",
  }),
});

export function createHostWorkspaceDeleteTool(
  root: string,
  options: DeleteToolOptions = {},
): AnyAgentTool {
  const workspaceOnly = options.workspaceOnly !== false;
  const base: AgentTool<typeof deleteToolSchema, DeleteToolDetails> = {
    name: "delete",
    label: "delete",
    description: DELETE_TOOL_DESCRIPTION,
    parameters: deleteToolSchema,
    execute: async (_toolCallId, args) => {
      const record = normalizeToolParams(args) ?? (args as Record<string, unknown> | undefined);
      const inputPath = typeof record?.path === "string" ? record.path : "";
      const target = await resolveDeleteTarget({
        root,
        inputPath,
        workspaceOnly,
      });
      enforceTrustedScopeForPath({
        args: record ?? args,
        absolutePath: target.resolved,
        expectedAction: "delete",
        config: resolveTrustedIsolationConfig(),
      });
      if (workspaceOnly) {
        const relative = path.relative(root, target.resolved);
        await removePathWithinRoot({
          rootDir: root,
          relativePath: relative,
        });
      } else {
        await fs.unlink(target.resolved);
      }
      return textResult(`Deleted ${target.display}`, {
        status: "completed",
        deletedPath: target.display,
      });
    },
  };
  return wrapToolParamNormalization(base as unknown as AnyAgentTool, CLAUDE_PARAM_GROUPS.delete);
}

export function createSandboxedDeleteTool(
  params: SandboxToolParams,
  options: DeleteToolOptions = {},
): AnyAgentTool {
  const workspaceOnly = options.workspaceOnly !== false;
  const base: AgentTool<typeof deleteToolSchema, DeleteToolDetails> = {
    name: "delete",
    label: "delete",
    description: DELETE_TOOL_DESCRIPTION,
    parameters: deleteToolSchema,
    execute: async (_toolCallId, args) => {
      const record = normalizeToolParams(args) ?? (args as Record<string, unknown> | undefined);
      const inputPath = typeof record?.path === "string" ? record.path : "";
      const target = await resolveSandboxDeleteTarget({
        root: params.root,
        bridge: params.bridge,
        inputPath,
        workspaceOnly,
      });
      enforceTrustedScopeForPath({
        args: record ?? args,
        absolutePath: target.hostPath ?? target.containerPath,
        expectedAction: "delete",
        config: resolveTrustedIsolationConfig(),
      });
      await params.bridge.remove({
        filePath: target.hostPath ?? target.containerPath,
        cwd: params.root,
        force: false,
      });
      return textResult(`Deleted ${target.display}`, {
        status: "completed",
        deletedPath: target.display,
      });
    },
  };
  return wrapToolParamNormalization(base as unknown as AnyAgentTool, CLAUDE_PARAM_GROUPS.delete);
}

async function resolveDeleteTarget(params: {
  root: string;
  inputPath: string;
  workspaceOnly: boolean;
}): Promise<{ resolved: string; display: string }> {
  if (!params.inputPath.trim()) {
    throw new ToolInputError("path required");
  }
  const resolved = params.workspaceOnly
    ? (
        await assertSandboxPath({
          filePath: params.inputPath,
          cwd: params.root,
          root: params.root,
          allowFinalSymlinkForUnlink: PATH_ALIAS_POLICIES.unlinkTarget.allowFinalSymlinkForUnlink,
          allowFinalHardlinkForUnlink: PATH_ALIAS_POLICIES.unlinkTarget.allowFinalHardlinkForUnlink,
        })
      ).resolved
    : resolvePathFromInput(params.inputPath, params.root);
  await assertDeleteableFile(resolved);
  return {
    resolved,
    display: toDisplayPath(resolved, params.root),
  };
}

async function resolveSandboxDeleteTarget(params: {
  root: string;
  bridge: SandboxFsBridge;
  inputPath: string;
  workspaceOnly: boolean;
}) {
  if (!params.inputPath.trim()) {
    throw new ToolInputError("path required");
  }
  const resolved = params.bridge.resolvePath({
    filePath: params.inputPath,
    cwd: params.root,
  });
  if (params.workspaceOnly && resolved.hostPath) {
    await assertSandboxPath({
      filePath: resolved.hostPath,
      cwd: params.root,
      root: params.root,
      allowFinalSymlinkForUnlink: PATH_ALIAS_POLICIES.unlinkTarget.allowFinalSymlinkForUnlink,
      allowFinalHardlinkForUnlink: PATH_ALIAS_POLICIES.unlinkTarget.allowFinalHardlinkForUnlink,
    });
  }
  const stat = await params.bridge.stat({
    filePath: resolved.hostPath ?? resolved.containerPath,
    cwd: params.root,
  });
  if (!stat) {
    throw new ToolInputError(`file not found: ${params.inputPath}`);
  }
  if (stat.type === "directory") {
    throw new ToolInputError("delete only supports single files; directories are not allowed");
  }
  if (stat.type !== "file") {
    throw new ToolInputError("delete only supports single files");
  }
  return {
    ...resolved,
    display: resolved.relativePath || resolved.containerPath,
  };
}

async function assertDeleteableFile(absolutePath: string): Promise<void> {
  let stat: Awaited<ReturnType<typeof fs.lstat>>;
  try {
    stat = await fs.lstat(absolutePath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException | undefined)?.code === "ENOENT") {
      throw new ToolInputError(`file not found: ${absolutePath}`);
    }
    throw error;
  }
  if (stat.isDirectory()) {
    throw new ToolInputError("delete only supports single files; directories are not allowed");
  }
  if (!stat.isFile() && !stat.isSymbolicLink()) {
    throw new ToolInputError("delete only supports single files");
  }
}

function toDisplayPath(resolved: string, cwd: string): string {
  const relative = path.relative(cwd, resolved);
  if (!relative || relative === "") {
    return path.basename(resolved);
  }
  if (relative.startsWith("..") || path.isAbsolute(relative)) {
    return resolved;
  }
  return relative;
}
