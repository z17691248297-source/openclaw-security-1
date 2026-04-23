import { spawn } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";

const DEFAULT_SERVICE_NAME = "openclaw-trusted-backend";
const DEFAULT_GUEST_ID_PREFIX = "tdx-guest";
const DEFAULT_COMMAND_TIMEOUT_MS = 2_000;

function trimText(value) {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function readPositiveIntEnv(name, fallback) {
  const raw = trimText(process.env[name]);
  if (!raw) {
    return fallback;
  }
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function normalizeHex(value) {
  const trimmed = trimText(value)?.replace(/^0x/i, "").replace(/\s+/g, "");
  if (!trimmed || !/^[0-9a-f]+$/i.test(trimmed) || trimmed.length % 2 !== 0) {
    return undefined;
  }
  return trimmed.toLowerCase();
}

function normalizeBase64(value) {
  const trimmed = trimText(value)?.replace(/\s+/g, "");
  if (!trimmed) {
    return undefined;
  }
  try {
    return Buffer.from(trimmed, "base64").toString("base64");
  } catch {
    return undefined;
  }
}

function decodeQuoteBuffer(payload) {
  const quoteHex = normalizeHex(payload?.quoteHex);
  if (quoteHex) {
    return Buffer.from(quoteHex, "hex");
  }
  const quoteBase64 =
    normalizeBase64(payload?.quoteBase64) ?? normalizeBase64(payload?.quote) ?? undefined;
  if (quoteBase64) {
    return Buffer.from(quoteBase64, "base64");
  }
  return undefined;
}

function buildRequestBinding(params) {
  const canonical = JSON.stringify({
    phase: params.phase,
    reqId: params.request?.reqId,
    requestDigest: params.request?.requestDigest,
    normalizedScopeDigest: params.request?.normalizedScopeDigest,
  });
  const nonceHex = sha256Hex(canonical);
  return {
    phase: params.phase,
    reqId: trimText(params.request?.reqId),
    requestDigest: trimText(params.request?.requestDigest),
    normalizedScopeDigest: trimText(params.request?.normalizedScopeDigest),
    nonceHex,
    nonceSha256: sha256Hex(nonceHex),
  };
}

function normalizeAttestationPayload(payload, source) {
  const quoteBuffer = decodeQuoteBuffer(payload);
  const measurement =
    normalizeHex(payload?.measurement) ??
    normalizeHex(payload?.mrTd) ??
    normalizeHex(payload?.mrtd) ??
    undefined;
  return {
    source,
    guestId: trimText(payload?.guestId),
    serviceName: trimText(payload?.serviceName),
    measurement,
    quoteFormat: trimText(payload?.quoteFormat) ?? trimText(payload?.format),
    reportDataHex:
      normalizeHex(payload?.reportDataHex) ?? normalizeHex(payload?.reportData) ?? undefined,
    svn: trimText(payload?.svn) ?? trimText(payload?.teeTcbSvn),
    mrConfigId: normalizeHex(payload?.mrConfigId) ?? normalizeHex(payload?.mrconfigid) ?? undefined,
    mrSeam: normalizeHex(payload?.mrSeam) ?? normalizeHex(payload?.mrseam) ?? undefined,
    quoteBuffer,
  };
}

async function readAttestationFile(filePath) {
  const raw = await fs.readFile(path.resolve(filePath), "utf8");
  return normalizeAttestationPayload(JSON.parse(raw), "file");
}

async function runAttestationCommand(command, env, timeoutMs) {
  return await new Promise((resolve, reject) => {
    const child = spawn("/bin/sh", ["-lc", command], {
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout = [];
    const stderr = [];
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) {
        return;
      }
      settled = true;
      child.kill("SIGTERM");
      reject(new Error("tdx attestation command timed out"));
    }, timeoutMs);

    child.stdout?.on("data", (chunk) => stdout.push(Buffer.from(chunk)));
    child.stderr?.on("data", (chunk) => stderr.push(Buffer.from(chunk)));
    child.once("error", (error) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      reject(error);
    });
    child.once("exit", (code, signal) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      if (code !== 0) {
        reject(
          new Error(
            `tdx attestation command failed (${signal || code || "unknown"}): ${Buffer.concat(
              stderr,
            )
              .toString("utf8")
              .trim()}`,
          ),
        );
        return;
      }
      resolve(Buffer.concat(stdout).toString("utf8"));
    });
  });
}

function summarizeAttestation(params) {
  const quoteBuffer = params.attestation.quoteBuffer;
  return {
    guestId: params.identity.guestId,
    serviceName: params.identity.serviceName,
    attestationMode: params.identity.attestationMode,
    source: params.attestation.source,
    attestedAtMs: params.attestedAtMs,
    measurement: params.attestation.measurement ?? params.identity.measurement,
    quoteFormat: params.attestation.quoteFormat ?? params.identity.quoteFormat,
    quoteSha256: quoteBuffer ? sha256Hex(quoteBuffer) : undefined,
    quoteBytes: quoteBuffer?.byteLength,
    reportDataHex: params.attestation.reportDataHex,
    requestBinding: params.binding,
    svn: params.attestation.svn,
    mrConfigId: params.attestation.mrConfigId,
    mrSeam: params.attestation.mrSeam,
  };
}

function resolveIdentity() {
  const hostname = os.hostname().trim() || "unknown";
  const measurement = normalizeHex(process.env.TRUSTED_TDX_MEASUREMENT);
  const quoteBuffer = decodeQuoteBuffer({
    quoteHex: process.env.TRUSTED_TDX_QUOTE_HEX,
    quoteBase64: process.env.TRUSTED_TDX_QUOTE_BASE64,
  });
  const attestationFile = trimText(process.env.TRUSTED_TDX_ATTESTATION_FILE);
  const attestationCommand = trimText(process.env.TRUSTED_TDX_ATTESTATION_COMMAND);
  let attestationMode = "none";
  if (attestationCommand) {
    attestationMode = "command";
  } else if (attestationFile) {
    attestationMode = "file";
  } else if (measurement || quoteBuffer) {
    attestationMode = "env";
  }
  return {
    guestId: trimText(process.env.TRUSTED_TDX_GUEST_ID) ?? `${DEFAULT_GUEST_ID_PREFIX}:${hostname}`,
    serviceName: trimText(process.env.TRUSTED_TDX_SERVICE_NAME) ?? DEFAULT_SERVICE_NAME,
    measurement,
    quoteFormat: trimText(process.env.TRUSTED_TDX_QUOTE_FORMAT) ?? undefined,
    quoteBuffer,
    attestationMode,
    attestationFile,
    attestationCommand,
    attestationCommandTimeoutMs: readPositiveIntEnv(
      "TRUSTED_TDX_ATTESTATION_COMMAND_TIMEOUT_MS",
      DEFAULT_COMMAND_TIMEOUT_MS,
    ),
  };
}

export function createLocalTdxGuestService() {
  const identity = resolveIdentity();

  async function loadAttestation(params) {
    if (identity.attestationMode === "file" && identity.attestationFile) {
      return await readAttestationFile(identity.attestationFile);
    }
    if (identity.attestationMode === "command" && identity.attestationCommand) {
      const raw = await runAttestationCommand(
        identity.attestationCommand,
        {
          ...process.env,
          TRUSTED_TDX_PHASE: params.binding.phase,
          TRUSTED_TDX_REQ_ID: params.binding.reqId ?? "",
          TRUSTED_TDX_REQUEST_DIGEST: params.binding.requestDigest ?? "",
          TRUSTED_TDX_NORMALIZED_SCOPE_DIGEST: params.binding.normalizedScopeDigest ?? "",
          TRUSTED_TDX_NONCE_HEX: params.binding.nonceHex,
        },
        identity.attestationCommandTimeoutMs,
      );
      return normalizeAttestationPayload(JSON.parse(raw), "command");
    }
    return normalizeAttestationPayload(
      {
        guestId: identity.guestId,
        serviceName: identity.serviceName,
        measurement: identity.measurement,
        quoteFormat: identity.quoteFormat,
        quoteBase64: identity.quoteBuffer?.toString("base64"),
      },
      identity.attestationMode === "env" ? "env" : "none",
    );
  }

  function buildGuestInfo(params = {}) {
    const quoteBuffer = identity.quoteBuffer;
    return {
      platform: "tdx",
      guestId: identity.guestId,
      serviceName: identity.serviceName,
      attestationMode: identity.attestationMode,
      attestationReady: identity.attestationMode !== "none",
      measurement: identity.measurement,
      quoteFormat: identity.quoteFormat,
      quoteSha256: quoteBuffer ? sha256Hex(quoteBuffer) : undefined,
      quoteBytes: quoteBuffer?.byteLength,
      ...(params.includeCommandConfig && identity.attestationMode === "command"
        ? { attestationCommandTimeoutMs: identity.attestationCommandTimeoutMs }
        : {}),
    };
  }

  return {
    getGuestInfo(params) {
      return buildGuestInfo(params);
    },
    async attest(params) {
      const binding = buildRequestBinding(params);
      const attestedAtMs = Date.now();
      const attestation = await loadAttestation({ binding });
      const resolvedIdentity = {
        ...identity,
        guestId: attestation.guestId ?? identity.guestId,
        serviceName: attestation.serviceName ?? identity.serviceName,
        measurement: attestation.measurement ?? identity.measurement,
        quoteFormat: attestation.quoteFormat ?? identity.quoteFormat,
      };
      return {
        guest: buildGuestInfo({ includeCommandConfig: true }),
        summary: summarizeAttestation({
          identity: resolvedIdentity,
          attestation,
          binding,
          attestedAtMs,
        }),
      };
    },
  };
}
