#!/usr/bin/env node

import path from "node:path";
import { validateTrustedEvidenceFile } from "../src/security/trusted-layer/evidence.ts";

function parseArgs(argv: string[]): { filePath?: string } {
  const result: { filePath?: string } = {};
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === "--file") {
      result.filePath = argv[index + 1];
      index += 1;
    }
  }
  return result;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const filePath =
    args.filePath?.trim() ||
    (process.env.OPENCLAW_STATE_DIR
      ? path.join(process.env.OPENCLAW_STATE_DIR, "security", "trusted-evidence.jsonl")
      : "");
  if (!filePath) {
    throw new Error("provide --file or set OPENCLAW_STATE_DIR");
  }
  const result = await validateTrustedEvidenceFile(filePath);
  console.log(JSON.stringify({ filePath, ...result }, null, 2));
  if (!result.ok) {
    process.exitCode = 1;
  }
}

void main().catch((error) => {
  console.error(error instanceof Error ? error.stack || error.message : String(error));
  process.exit(1);
});
