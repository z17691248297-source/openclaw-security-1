import crypto from "node:crypto";
import { createSubsystemLogger } from "../../logging/subsystem.js";
import { splitShellArgs } from "../../utils/shell-argv.js";
import type { TrustedIsolationConfig } from "../trusted-isolation/config.js";
import { digestTrustedValue } from "./digest.js";
import {
  createTrustedAuthorizationMissingScopeTokenError,
  createTrustedScopeTokenExpiredError,
  createTrustedScopeTokenVerificationFailedError,
  createTrustedScopeViolationError,
} from "./errors.js";
import type {
  TrustedIsolationAction,
  TrustedScopeEnvelope,
  TrustedScopeTokenPayload,
} from "./types.js";

const log = createSubsystemLogger("security/trusted-isolation");

export const TRUSTED_SCOPE_PARAM_KEY = "__openclawTrusted";

type VerifiedToken = {
  payload: TrustedScopeTokenPayload;
  signedInput: string;
};

function toBase64Url(input: Buffer | string): string {
  const raw = Buffer.isBuffer(input) ? input : Buffer.from(input, "utf8");
  return raw.toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function fromBase64Url(input: string): Buffer {
  const normalized = input.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  return Buffer.from(padded, "base64");
}

function normalizeRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" ? (value as Record<string, unknown>) : {};
}

function normalizePath(value: string): string {
  return value.replace(/\\/g, "/").replace(/\/+$|^\s+|\s+$/g, "");
}

function normalizeEnvSubset(input: unknown): Record<string, string> {
  if (!input || typeof input !== "object") {
    return {};
  }
  return Object.fromEntries(
    Object.entries(input as Record<string, unknown>)
      .filter(([, value]) => typeof value === "string")
      .toSorted(([left], [right]) => left.localeCompare(right)),
  ) as Record<string, string>;
}

function parseToken(token: string): VerifiedToken {
  const parts = token.split(".");
  if (parts.length !== 2) {
    throw createTrustedScopeTokenVerificationFailedError(new Error("invalid token format"));
  }
  const [payloadB64] = parts;
  if (!payloadB64) {
    throw createTrustedScopeTokenVerificationFailedError(new Error("missing token payload"));
  }
  try {
    return {
      payload: JSON.parse(fromBase64Url(payloadB64).toString("utf8")) as TrustedScopeTokenPayload,
      signedInput: payloadB64,
    };
  } catch (error) {
    throw createTrustedScopeTokenVerificationFailedError(error);
  }
}

function verifyTokenSignature(params: {
  token: string;
  signedInput: string;
  config: TrustedIsolationConfig;
}): boolean {
  const parts = params.token.split(".");
  const signatureB64 = parts[1];
  if (!signatureB64) {
    return false;
  }
  const signature = fromBase64Url(signatureB64);

  if (params.config.verifyMode === "none") {
    return true;
  }

  if (params.config.verifyMode === "hmac-sha256") {
    const key = params.config.hmacKey?.trim();
    if (!key) {
      return false;
    }
    const mac = crypto.createHmac("sha256", key).update(params.signedInput).digest();
    if (mac.length !== signature.length) {
      return false;
    }
    return crypto.timingSafeEqual(mac, signature);
  }

  if (params.config.verifyMode === "ed25519") {
    const publicKeyPem = params.config.publicKeyPem?.trim();
    if (!publicKeyPem) {
      return false;
    }
    try {
      return crypto.verify(
        null,
        Buffer.from(params.signedInput, "utf8"),
        crypto.createPublicKey(publicKeyPem),
        signature,
      );
    } catch {
      return false;
    }
  }

  return false;
}

export function applyTrustedScopeToParams(params: {
  inputParams: unknown;
  envelope: TrustedScopeEnvelope;
}): Record<string, unknown> {
  return {
    ...normalizeRecord(params.inputParams),
    [TRUSTED_SCOPE_PARAM_KEY]: params.envelope,
  };
}

export function extractTrustedScopeEnvelope(params: unknown): TrustedScopeEnvelope | undefined {
  const record = normalizeRecord(params);
  const envelope = record[TRUSTED_SCOPE_PARAM_KEY];
  if (!envelope || typeof envelope !== "object") {
    return undefined;
  }
  const value = envelope as Partial<TrustedScopeEnvelope>;
  if (
    !value.token ||
    !value.reqId ||
    !value.sid ||
    !value.action ||
    !value.object ||
    !value.normalizedScopeDigest
  ) {
    return undefined;
  }
  return value as TrustedScopeEnvelope;
}

function verifyTrustedScopeToken(params: {
  token: string;
  config: TrustedIsolationConfig;
  expectedReqId: string;
  expectedSid?: string;
  expectedAction: TrustedIsolationAction;
  expectedObject: string;
  expectedScopeDigest: string;
}): TrustedScopeTokenPayload {
  const parsed = parseToken(params.token);
  if (
    !verifyTokenSignature({
      token: params.token,
      signedInput: parsed.signedInput,
      config: params.config,
    })
  ) {
    throw createTrustedScopeTokenVerificationFailedError();
  }
  if (typeof parsed.payload.expiresAtMs !== "number" || parsed.payload.expiresAtMs < Date.now()) {
    throw createTrustedScopeTokenExpiredError();
  }
  if (parsed.payload.reqId !== params.expectedReqId) {
    throw createTrustedScopeViolationError("request id differs from approved request");
  }
  if (params.expectedSid && parsed.payload.sid !== params.expectedSid) {
    throw createTrustedScopeViolationError("session id differs from approved session");
  }
  if (parsed.payload.action !== params.expectedAction) {
    throw createTrustedScopeViolationError("action differs from approved action");
  }
  if (parsed.payload.object !== params.expectedObject) {
    throw createTrustedScopeViolationError("object differs from approved object");
  }
  if (parsed.payload.normalizedScopeDigest !== params.expectedScopeDigest) {
    throw createTrustedScopeViolationError("scope digest differs from approved scope");
  }
  return parsed.payload;
}

function ensureScopeMatchForPath(params: {
  payload: TrustedScopeTokenPayload;
  absolutePath: string;
}): void {
  const allowedPath = params.payload.scope.allowedPath;
  const allowedPrefixes = params.payload.scope.allowedPrefixes ?? [];

  if (allowedPath && normalizePath(allowedPath) === normalizePath(params.absolutePath)) {
    return;
  }
  if (
    allowedPrefixes.some((prefix) => {
      const normalizedPrefix = normalizePath(prefix);
      const normalizedPath = normalizePath(params.absolutePath);
      return (
        normalizedPath === normalizedPrefix || normalizedPath.startsWith(`${normalizedPrefix}/`)
      );
    })
  ) {
    return;
  }

  throw createTrustedScopeViolationError("file path not within approved scope");
}

function ensureScopeMatchForExec(params: {
  payload: TrustedScopeTokenPayload;
  command: string;
  workdir?: string;
  env?: Record<string, string>;
}): void {
  const execScope = params.payload.scope.exec;
  if (!execScope) {
    return;
  }
  if (execScope.rawCommand.trim() !== params.command.trim()) {
    throw createTrustedScopeViolationError("command differs from approved command");
  }
  if (execScope.matchMode === "exact") {
    const parsedActual = splitShellArgs(params.command);
    if (execScope.command && execScope.command !== (parsedActual?.[0] ?? params.command.trim())) {
      throw createTrustedScopeViolationError("command binary differs from approved command");
    }
    const actualArgs = parsedActual?.slice(1) ?? [];
    if (JSON.stringify(execScope.args) !== JSON.stringify(actualArgs)) {
      throw createTrustedScopeViolationError("command arguments differ from approved command");
    }
  }
  if (execScope.cwd && normalizePath(execScope.cwd) !== normalizePath(params.workdir ?? "")) {
    throw createTrustedScopeViolationError("working directory differs from approved cwd");
  }
  if (execScope.envSubset) {
    const actualEnvSubset = normalizeEnvSubset(params.env);
    if (JSON.stringify(execScope.envSubset) !== JSON.stringify(actualEnvSubset)) {
      throw createTrustedScopeViolationError("environment overrides differ from approved scope");
    }
  }
}

export function verifyAuthorizedExecScope(params: {
  args: unknown;
  command: string;
  workdir?: string;
  env?: Record<string, string>;
  expectedSid?: string;
  config: TrustedIsolationConfig;
}): TrustedScopeTokenPayload | undefined {
  const envelope = extractTrustedScopeEnvelope(params.args);
  if (!envelope) {
    return undefined;
  }
  const payload = verifyTrustedScopeToken({
    token: envelope.token,
    config: params.config,
    expectedReqId: envelope.reqId,
    expectedSid: params.expectedSid ?? envelope.sid,
    expectedAction: envelope.action,
    expectedObject: envelope.object,
    expectedScopeDigest: envelope.normalizedScopeDigest,
  });
  if (payload.action !== "exec") {
    throw createTrustedScopeViolationError("expected exec token");
  }
  ensureScopeMatchForExec({
    payload,
    command: params.command,
    workdir: params.workdir,
    env: params.env,
  });
  return payload;
}

export function enforceTrustedScopeForExec(params: {
  toolName: string;
  args: unknown;
  command: string;
  workdir?: string;
  env?: Record<string, string>;
  expectedSid?: string;
  config: TrustedIsolationConfig;
}): void {
  const scopeEnvelope = extractTrustedScopeEnvelope(params.args);
  const trustedScopeRequired =
    params.config.enabled &&
    params.config.requireScopeToken &&
    (params.config.forceTrustedActions.includes("exec") ||
      params.config.forceTrustedTools.includes(params.toolName));
  if (!scopeEnvelope) {
    if (trustedScopeRequired) {
      throw createTrustedAuthorizationMissingScopeTokenError();
    }
    return;
  }
  void verifyAuthorizedExecScope({
    args: params.args,
    command: params.command,
    workdir: params.workdir,
    env: params.env,
    expectedSid: params.expectedSid,
    config: params.config,
  });
}

export function enforceTrustedScopeForPath(params: {
  args: unknown;
  absolutePath: string;
  expectedAction: "read" | "modify" | "delete";
  expectedSid?: string;
  config: TrustedIsolationConfig;
}): void {
  const envelope = extractTrustedScopeEnvelope(params.args);
  if (!envelope) {
    return;
  }
  const payload = verifyTrustedScopeToken({
    token: envelope.token,
    config: params.config,
    expectedReqId: envelope.reqId,
    expectedSid: params.expectedSid ?? envelope.sid,
    expectedAction: envelope.action,
    expectedObject: envelope.object,
    expectedScopeDigest: envelope.normalizedScopeDigest,
  });
  if (
    payload.action !== params.expectedAction &&
    !(payload.action === "modify" && params.expectedAction === "read")
  ) {
    throw createTrustedScopeViolationError("action differs from approved action");
  }
  ensureScopeMatchForPath({ payload, absolutePath: params.absolutePath });
}

export function enforceTrustedScopeForPatch(params: {
  args: unknown;
  absolutePath: string;
  expectedSid?: string;
  config: TrustedIsolationConfig;
}): void {
  const envelope = extractTrustedScopeEnvelope(params.args);
  if (!envelope) {
    return;
  }
  const payload = verifyTrustedScopeToken({
    token: envelope.token,
    config: params.config,
    expectedReqId: envelope.reqId,
    expectedSid: params.expectedSid ?? envelope.sid,
    expectedAction: envelope.action,
    expectedObject: envelope.object,
    expectedScopeDigest: envelope.normalizedScopeDigest,
  });
  if (payload.action !== "modify") {
    throw createTrustedScopeViolationError("patch requires modify token");
  }
  ensureScopeMatchForPath({ payload, absolutePath: params.absolutePath });
}

export function digestObject(input: unknown): string {
  return digestTrustedValue(input);
}

export function softLogScopeValidationError(message: string): void {
  log.warn(`trusted scope validation failed: ${message}`);
}

export function encodeUnsignedTokenPayload(payload: TrustedScopeTokenPayload): string {
  return `${toBase64Url(JSON.stringify(payload))}.`;
}
