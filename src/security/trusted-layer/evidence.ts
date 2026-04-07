import fs from "node:fs/promises";
import path from "node:path";
import { resolveStateDir } from "../../config/paths.js";
import { createSubsystemLogger } from "../../logging/subsystem.js";
import { digestTrustedValue } from "./digest.js";
import { createTrustedEvidenceWriteFailureError } from "./errors.js";
import type { TrustedEvidenceRecord } from "./types.js";

const log = createSubsystemLogger("security/trusted-isolation");
const tailHashByFile = new Map<string, string>();

export function resolveTrustedEvidencePath(configuredPath?: string): string {
  const trimmed = configuredPath?.trim();
  if (trimmed) {
    return trimmed;
  }
  return path.join(resolveStateDir(process.env), "security", "trusted-evidence.jsonl");
}

async function resolveTailHash(filePath: string): Promise<string> {
  const cached = tailHashByFile.get(filePath);
  if (cached !== undefined) {
    return cached;
  }
  try {
    const raw = await fs.readFile(filePath, "utf8");
    const lastLine = raw
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean)
      .at(-1);
    if (!lastLine) {
      tailHashByFile.set(filePath, "");
      return "";
    }
    const parsed = JSON.parse(lastLine) as { entryHash?: unknown };
    const tailHash = typeof parsed.entryHash === "string" ? parsed.entryHash : "";
    tailHashByFile.set(filePath, tailHash);
    return tailHash;
  } catch {
    tailHashByFile.set(filePath, "");
    return "";
  }
}

export async function appendTrustedEvidenceRecord(params: {
  filePath?: string;
  record: Omit<TrustedEvidenceRecord, "entryHash" | "prevHash">;
}): Promise<void> {
  const evidencePath = resolveTrustedEvidencePath(params.filePath);
  try {
    await fs.mkdir(path.dirname(evidencePath), { recursive: true });
    const prevHash = await resolveTailHash(evidencePath);
    const canonicalRecord = {
      ...params.record,
      prevHash,
    };
    const entryHash = digestTrustedValue(canonicalRecord);
    await fs.appendFile(
      evidencePath,
      `${JSON.stringify({ ...canonicalRecord, entryHash })}\n`,
      "utf8",
    );
    tailHashByFile.set(evidencePath, entryHash);
  } catch (error) {
    throw createTrustedEvidenceWriteFailureError(error);
  }
}

export async function readTrustedEvidenceRecords(
  filePath: string,
): Promise<TrustedEvidenceRecord[]> {
  const raw = await fs.readFile(filePath, "utf8");
  return raw
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => JSON.parse(line) as TrustedEvidenceRecord);
}

export function validateTrustedEvidenceRecords(records: TrustedEvidenceRecord[]): {
  ok: boolean;
  errors: string[];
  summary: {
    entryCount: number;
    reqIds: number;
    authorizePairs: number;
  };
} {
  const errors: string[] = [];
  let previousHash = "";
  const byReqId = new Map<string, TrustedEvidenceRecord[]>();

  records.forEach((record, index) => {
    const line = index + 1;
    if ((record.prevHash ?? "") !== previousHash) {
      errors.push(`line ${line}: prevHash continuity mismatch`);
    }
    const { entryHash: _entryHash, ...rest } = record;
    const expectedEntryHash = digestTrustedValue(rest);
    if (record.entryHash !== expectedEntryHash) {
      errors.push(`line ${line}: entryHash mismatch`);
    }
    previousHash = record.entryHash ?? "";
    const group = byReqId.get(record.reqId) ?? [];
    group.push(record);
    byReqId.set(record.reqId, group);
  });

  let authorizePairs = 0;
  for (const [reqId, group] of byReqId) {
    const authorizeEvents = group.filter((record) => record.event === "authorize");
    const confirmEvents = group.filter((record) => record.event === "confirm");
    const completeEvents = group.filter((record) => record.event === "complete");
    const violationEvents = group.filter((record) => record.event === "violation");
    const denyEvents = group.filter((record) => record.event === "deny");

    if (authorizeEvents.length > 1) {
      errors.push(`reqId ${reqId}: multiple authorize events`);
    }
    if (confirmEvents.length > 1) {
      errors.push(`reqId ${reqId}: multiple confirm events`);
    }
    const base = authorizeEvents[0] ?? group[0];
    for (const record of group) {
      if (record.action !== base?.action) {
        errors.push(`reqId ${reqId}: action mismatch across evidence records`);
      }
      if (record.object !== base?.object) {
        errors.push(`reqId ${reqId}: object mismatch across evidence records`);
      }
      if (record.normalizedScopeDigest !== base?.normalizedScopeDigest) {
        errors.push(`reqId ${reqId}: normalizedScopeDigest mismatch across evidence records`);
      }
      if (record.requestDigest !== base?.requestDigest) {
        errors.push(`reqId ${reqId}: requestDigest mismatch across evidence records`);
      }
    }
    if (confirmEvents.length > 0 && authorizeEvents.length !== 1) {
      errors.push(`reqId ${reqId}: confirmation evidence requires exactly one authorize`);
    }
    if ((completeEvents.length > 0 || violationEvents.length > 0) && authorizeEvents.length !== 1) {
      errors.push(`reqId ${reqId}: terminal execution evidence requires exactly one authorize`);
    }
    if (completeEvents.length > 1) {
      errors.push(`reqId ${reqId}: multiple complete events`);
    }
    if (violationEvents.length > 1) {
      errors.push(`reqId ${reqId}: multiple violation events`);
    }
    if (denyEvents.length > 1) {
      errors.push(`reqId ${reqId}: multiple deny events`);
    }
    if (denyEvents.length > 0 && (completeEvents.length > 0 || violationEvents.length > 0)) {
      errors.push(`reqId ${reqId}: deny must not coexist with terminal execution evidence`);
    }
    const approvedConfirm = confirmEvents.find(
      (record) => record.confirmationStatus === "approved",
    );
    if (approvedConfirm && denyEvents.length > 0) {
      errors.push(`reqId ${reqId}: approved confirm must not coexist with deny`);
    }
    const deniedConfirm = confirmEvents.find((record) => record.confirmationStatus === "denied");
    if (deniedConfirm && (completeEvents.length > 0 || violationEvents.length > 0)) {
      errors.push(`reqId ${reqId}: denied confirm must not coexist with execution evidence`);
    }
    if (authorizeEvents.length === 1 && completeEvents.length === 1) {
      authorizePairs += 1;
    }
  }

  return {
    ok: errors.length === 0,
    errors,
    summary: {
      entryCount: records.length,
      reqIds: byReqId.size,
      authorizePairs,
    },
  };
}

export async function validateTrustedEvidenceFile(filePath: string): Promise<{
  ok: boolean;
  errors: string[];
  summary: {
    entryCount: number;
    reqIds: number;
    authorizePairs: number;
  };
}> {
  return validateTrustedEvidenceRecords(await readTrustedEvidenceRecords(filePath));
}

export function logTrustedEvidenceFailure(error: unknown): void {
  log.warn(`trusted evidence write failed: ${String(error)}`);
}
