import fs from "node:fs/promises";
import type {
  TrustedBackendHandle,
  TrustedIsolationHarness,
} from "../../../../scripts/lib/trusted-isolation/harness.ts";

let nextPort = 19350;

export function allocateTrustedTestPort(): number {
  const port = nextPort;
  nextPort += 1;
  return port;
}

export async function cleanupTrustedIsolationTest(params: {
  harness: TrustedIsolationHarness;
  backend?: TrustedBackendHandle;
}): Promise<void> {
  await params.backend?.stop().catch(() => undefined);
  await fs.rm(params.harness.rootDir, { recursive: true, force: true });
}

export function groupEvidenceByReqId(
  records: Array<Record<string, unknown>>,
): Map<string, string[]> {
  const grouped = new Map<string, string[]>();
  for (const entry of records) {
    const reqId = typeof entry.reqId === "string" ? entry.reqId : "";
    const event = typeof entry.event === "string" ? entry.event : "";
    if (!reqId || !event) {
      continue;
    }
    const group = grouped.get(reqId) ?? [];
    group.push(event);
    grouped.set(reqId, group);
  }
  return grouped;
}
