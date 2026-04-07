#!/usr/bin/env node

import { spawnSync } from "node:child_process";

const [scriptName, ...extraArgs] = process.argv.slice(2);

if (!scriptName) {
  console.error("Usage: node scripts/run-package-script.mjs <script-name> [...args]");
  process.exit(1);
}

function run(command, args) {
  return spawnSync(command, args, {
    encoding: "utf8",
    stdio: "inherit",
    shell: process.platform === "win32",
  });
}

const direct = run("pnpm", ["run", scriptName, ...extraArgs]);
if (!direct.error || direct.error.code !== "ENOENT") {
  process.exit(typeof direct.status === "number" ? direct.status : 1);
}

const fallback = run("corepack", ["pnpm", "run", scriptName, ...extraArgs]);
if (fallback.error) {
  console.error(`Failed to start package script runner: ${fallback.error.message}`);
  process.exit(1);
}

process.exit(typeof fallback.status === "number" ? fallback.status : 1);
