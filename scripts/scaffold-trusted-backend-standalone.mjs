#!/usr/bin/env node

import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const CANONICAL_TRUSTED_BACKEND_DIR = path.join(
  __dirname,
  "..",
  "external",
  "openclaw-trusted-backend",
);
const CANONICAL_BACKEND_FILES = [
  "server.mjs",
  "policy.mjs",
  "adaptors.mjs",
  "tdx-guest.mjs",
  "openclaw-trusted-backend.service.example",
  "openclaw-trusted-backend.env.example",
  "package.json",
  ".env.example",
  "policy.json",
  "README.md",
  ".gitignore",
];

async function ensureCleanTarget(targetDir, force) {
  if (!force) {
    try {
      await fs.access(targetDir);
      throw new Error(`target directory already exists: ${targetDir}`);
    } catch (error) {
      if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
        return;
      }
      throw error;
    }
  }
  await fs.rm(targetDir, { recursive: true, force: true });
}

async function copyBackendModule(params) {
  const sourcePath = path.join(CANONICAL_TRUSTED_BACKEND_DIR, params.fileName);
  const targetPath = path.join(params.targetDir, params.fileName);
  const content = await fs.readFile(sourcePath, "utf8");
  await fs.writeFile(targetPath, content, "utf8");
}

export async function scaffoldTrustedBackendStandalone(params) {
  const targetDir = path.resolve(params.targetDir);
  const canonicalDir = path.resolve(CANONICAL_TRUSTED_BACKEND_DIR);
  if (targetDir === canonicalDir) {
    throw new Error(
      `refusing to scaffold over canonical trusted backend source directory: ${canonicalDir}`,
    );
  }
  await ensureCleanTarget(targetDir, params.force === true);
  await fs.mkdir(targetDir, { recursive: true });
  await fs.mkdir(path.join(targetDir, "logs"), { recursive: true });

  for (const fileName of CANONICAL_BACKEND_FILES) {
    await copyBackendModule({ fileName, targetDir });
  }

  return {
    targetDir,
    files: CANONICAL_BACKEND_FILES,
  };
}

function parseArgs(argv) {
  const result = {
    targetDir: "",
    force: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (value === "--force") {
      result.force = true;
      continue;
    }
    if (value === "--target") {
      result.targetDir = argv[index + 1] ?? "";
      index += 1;
      continue;
    }
  }
  return result;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const targetDir =
    args.targetDir.trim() || path.resolve(process.cwd(), "openclaw-trusted-backend");
  const result = await scaffoldTrustedBackendStandalone({
    targetDir,
    force: args.force,
  });
  console.log(JSON.stringify(result, null, 2));
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  void main().catch((error) => {
    console.error(error instanceof Error ? error.stack || error.message : String(error));
    process.exit(1);
  });
}
