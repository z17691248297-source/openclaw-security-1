import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createHostWorkspaceDeleteTool } from "./pi-tools.delete.js";

const tempDirs: string[] = [];

afterEach(async () => {
  await Promise.all(
    tempDirs.splice(0, tempDirs.length).map((dir) => fs.rm(dir, { recursive: true, force: true })),
  );
});

async function createWorkspace(): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-delete-tool-"));
  tempDirs.push(dir);
  return dir;
}

describe("createHostWorkspaceDeleteTool", () => {
  it("deletes a single workspace file, including binary files", async () => {
    const workspaceDir = await createWorkspace();
    const filePath = path.join(workspaceDir, "duc-test.tgz");
    await fs.writeFile(filePath, Buffer.from([0x1f, 0x8b, 0x08, 0x00]));

    const tool = createHostWorkspaceDeleteTool(workspaceDir);
    const result = await tool.execute("call-1", { file_path: "duc-test.tgz" });

    await expect(fs.stat(filePath)).rejects.toMatchObject({ code: "ENOENT" });
    expect(result.content[0]?.type).toBe("text");
    expect((result.content[0] as { text?: string }).text).toContain("Deleted duc-test.tgz");
    expect(result.details).toEqual({
      status: "completed",
      deletedPath: "duc-test.tgz",
    });
  });

  it("rejects directories", async () => {
    const workspaceDir = await createWorkspace();
    await fs.mkdir(path.join(workspaceDir, "docs"));

    const tool = createHostWorkspaceDeleteTool(workspaceDir);

    await expect(tool.execute("call-2", { path: "docs" })).rejects.toThrow(
      "delete only supports single files; directories are not allowed",
    );
  });

  it("rejects paths outside the workspace", async () => {
    const workspaceDir = await createWorkspace();
    const outsidePath = path.join(path.dirname(workspaceDir), "outside.txt");
    await fs.writeFile(outsidePath, "keep");

    const tool = createHostWorkspaceDeleteTool(workspaceDir);

    await expect(tool.execute("call-3", { path: "../outside.txt" })).rejects.toThrow();
    await expect(fs.readFile(outsidePath, "utf8")).resolves.toBe("keep");
    await fs.rm(outsidePath, { force: true });
  });
});
