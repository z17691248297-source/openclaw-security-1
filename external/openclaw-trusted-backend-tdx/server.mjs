import crypto from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createTrustedBackendAdaptor } from "./adaptors.mjs";
import {
  DEFAULT_TRUSTED_POLICY,
  decisionForConfirmedExecutionMode,
  evaluateTrustedAuthorizeRequest,
  loadTrustedPolicy,
} from "./policy.mjs";

const __filename = fileURLToPath(import.meta.url);
let tailHash = "";
const pendingConfirmations = new Map();
const DEFAULT_CONFIRMATION_TIMEOUT_MS = 30 * 60 * 1000;
const DEFAULT_EXPIRED_CONFIRMATION_RETENTION_MS = 5 * 60 * 1000;

function toBase64Url(input) {
  const raw = Buffer.isBuffer(input) ? input : Buffer.from(input, "utf8");
  return raw.toString("base64").replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function timingSafeTextEqual(left, right) {
  const a = Buffer.from(String(left ?? ""), "utf8");
  const b = Buffer.from(String(right ?? ""), "utf8");
  if (a.length !== b.length) {
    return false;
  }
  return crypto.timingSafeEqual(a, b);
}

function json(statusCode, payload) {
  return {
    statusCode,
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  };
}

function readPositiveIntEnv(name, fallback) {
  const raw = process.env[name]?.trim();
  if (!raw) {
    return fallback;
  }
  const parsed = Number.parseInt(raw, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function resolveEventsFile() {
  const configured = process.env.TRUSTED_BACKEND_EVENTS_FILE?.trim();
  if (configured) {
    return path.resolve(configured);
  }
  return path.resolve("logs", "trusted-backend-events.jsonl");
}

export async function resolveTailHash(filePath) {
  try {
    const raw = await fs.readFile(path.resolve(filePath), "utf8");
    const lastLine = raw
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean)
      .at(-1);
    if (!lastLine) {
      return "";
    }
    const parsed = JSON.parse(lastLine);
    return typeof parsed?.entryHash === "string" ? parsed.entryHash : "";
  } catch {
    return "";
  }
}

async function appendJsonl(filePath, payload) {
  const resolved = path.resolve(filePath);
  await fs.mkdir(path.dirname(resolved), { recursive: true });
  const chained = { ...payload, prevHash: tailHash };
  const canonical = JSON.stringify(chained);
  tailHash = crypto.createHash("sha256").update(canonical).digest("hex");
  await fs.appendFile(resolved, `${JSON.stringify({ ...chained, entryHash: tailHash })}\n`, "utf8");
}

async function readJsonBody(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const raw = Buffer.concat(chunks).toString("utf8").trim();
  return raw ? JSON.parse(raw) : {};
}

async function resolveEd25519PrivateKeyPem() {
  const inlinePem = process.env.TRUSTED_SIGNING_PRIVATE_KEY_PEM?.trim();
  if (inlinePem) {
    return inlinePem.replace(/\\n/g, "\n");
  }
  const filePath = process.env.TRUSTED_SIGNING_PRIVATE_KEY_FILE?.trim();
  if (!filePath) {
    return undefined;
  }
  return await fs.readFile(path.resolve(filePath), "utf8");
}

function resolveSigningMode() {
  return process.env.TRUSTED_VERIFY_MODE?.trim() || "hmac-sha256";
}

async function signScopePayload(payloadB64) {
  const mode = resolveSigningMode();
  if (mode === "hmac-sha256") {
    const hmacKey = process.env.TRUSTED_HMAC_KEY?.trim();
    if (!hmacKey) {
      throw new Error("TRUSTED_HMAC_KEY is required when TRUSTED_VERIFY_MODE=hmac-sha256");
    }
    return toBase64Url(crypto.createHmac("sha256", hmacKey).update(payloadB64).digest());
  }
  if (mode === "ed25519") {
    const privateKeyPem = await resolveEd25519PrivateKeyPem();
    if (!privateKeyPem) {
      throw new Error(
        "TRUSTED_SIGNING_PRIVATE_KEY_FILE or TRUSTED_SIGNING_PRIVATE_KEY_PEM is required when TRUSTED_VERIFY_MODE=ed25519",
      );
    }
    const signature = crypto.sign(
      null,
      Buffer.from(payloadB64, "utf8"),
      crypto.createPrivateKey(privateKeyPem),
    );
    return toBase64Url(signature);
  }
  throw new Error(`Unsupported TRUSTED_VERIFY_MODE: ${mode}`);
}

function buildScopeTokenPayload(request, overrides = {}) {
  const issuedAtMs =
    typeof overrides.issuedAtMs === "number" && Number.isFinite(overrides.issuedAtMs)
      ? overrides.issuedAtMs
      : request.issuedAtMs;
  const ttlMs =
    typeof overrides.ttlMs === "number" && Number.isFinite(overrides.ttlMs) && overrides.ttlMs > 0
      ? overrides.ttlMs
      : request.ttlMs;
  const expiresAtMs =
    typeof overrides.expiresAtMs === "number" && Number.isFinite(overrides.expiresAtMs)
      ? overrides.expiresAtMs
      : issuedAtMs + ttlMs;
  return {
    version: 1,
    reqId: request.reqId,
    sid: request.sid,
    action: request.action,
    object: request.object,
    scope: request.scope,
    normalizedScopeDigest: request.normalizedScopeDigest,
    issuedAtMs,
    expiresAtMs,
  };
}

async function buildSignedToken(payload) {
  const payloadB64 = toBase64Url(JSON.stringify(payload));
  const signatureB64 = await signScopePayload(payloadB64);
  return `${payloadB64}.${signatureB64}`;
}

async function buildScopeToken(request, overrides) {
  return await buildSignedToken(buildScopeTokenPayload(request, overrides));
}

function buildConfirmationChallengePayload(params) {
  return {
    version: 1,
    confirmationRequestId: params.confirmationRequestId,
    reqId: params.request.reqId,
    sid: params.request.sid,
    normalizedScopeDigest: params.request.normalizedScopeDigest,
    executionMode: params.executionMode,
    issuedAtMs:
      typeof params.issuedAtMs === "number" && Number.isFinite(params.issuedAtMs)
        ? params.issuedAtMs
        : params.request.issuedAtMs,
    expiresAtMs: params.expiresAtMs,
  };
}

function buildConfirmationSummary(params) {
  const command = params.request?.scope?.exec?.rawCommand?.trim();
  return command || params.request?.object || params.reason;
}

function buildConfirmationPrompt(params) {
  const summary = buildConfirmationSummary(params);
  return `Trusted confirmation required: ${summary} (${params.reason})`;
}

function pruneExpiredConfirmations(
  now = Date.now(),
  retentionMs = DEFAULT_EXPIRED_CONFIRMATION_RETENTION_MS,
) {
  for (const [confirmationRequestId, pending] of pendingConfirmations) {
    if (pending.expiresAtMs + retentionMs < now) {
      pendingConfirmations.delete(confirmationRequestId);
    }
  }
}

export async function startTrustedBackendServer() {
  const host = process.env.TRUSTED_BACKEND_HOST?.trim() || "127.0.0.1";
  const port = Number.parseInt(process.env.TRUSTED_BACKEND_PORT ?? "19090", 10);
  const confirmationTimeoutMs = readPositiveIntEnv(
    "TRUSTED_CONFIRMATION_TIMEOUT_MS",
    DEFAULT_CONFIRMATION_TIMEOUT_MS,
  );
  const expiredConfirmationRetentionMs = readPositiveIntEnv(
    "TRUSTED_CONFIRMATION_EXPIRED_RETENTION_MS",
    DEFAULT_EXPIRED_CONFIRMATION_RETENTION_MS,
  );
  const eventsFile = resolveEventsFile();
  tailHash = await resolveTailHash(eventsFile);
  const adaptor = createTrustedBackendAdaptor(process.env.TRUSTED_BACKEND_ADAPTOR);
  const policy = await loadTrustedPolicy(process.env.TRUSTED_POLICY_PATH?.trim());

  const server = http.createServer(async (req, res) => {
    try {
      const method = req.method ?? "GET";
      const url = new URL(req.url ?? "/", `http://${host}:${port}`);
      pruneExpiredConfirmations(Date.now(), expiredConfirmationRetentionMs);

      if (method === "GET" && url.pathname === "/healthz") {
        const response = json(200, {
          ok: true,
          mode: resolveSigningMode(),
          adaptor: adaptor.adaptor,
          platform: adaptor.platform,
          policyVersion: DEFAULT_TRUSTED_POLICY.version,
          guest: typeof adaptor.getGuestInfo === "function" ? adaptor.getGuestInfo() : undefined,
        });
        res.writeHead(response.statusCode, response.headers);
        res.end(response.body);
        return;
      }

      if (method === "GET" && url.pathname === "/v1/trusted/guest") {
        if (typeof adaptor.getGuestInfo !== "function") {
          const response = json(404, { error: "guest_info_unavailable" });
          res.writeHead(response.statusCode, response.headers);
          res.end(response.body);
          return;
        }
        const includeAttestation = url.searchParams.get("attest") === "1";
        const guest = adaptor.getGuestInfo({ includeCommandConfig: true });
        const attestation =
          includeAttestation && typeof adaptor.attest === "function"
            ? await adaptor.attest({
                phase: "guest-info",
                request: {
                  reqId: "guest-info",
                  requestDigest: "guest-info",
                  normalizedScopeDigest: "guest-info",
                },
              })
            : undefined;
        const response = json(200, {
          ok: true,
          adaptor: adaptor.adaptor,
          platform: adaptor.platform,
          guest,
          attestation: attestation?.summary,
        });
        res.writeHead(response.statusCode, response.headers);
        res.end(response.body);
        return;
      }

      if (method === "POST" && url.pathname === "/v1/trusted/authorize") {
        const request = await readJsonBody(req);
        const evaluation = evaluateTrustedAuthorizeRequest(request, policy);
        const adaptorResult = await adaptor.authorize({ request, evaluation });
        let confirmation;
        if (evaluation.decision === "duc") {
          const confirmationIssuedAtMs = Date.now();
          const expiresAtMs = confirmationIssuedAtMs + confirmationTimeoutMs;
          const confirmationRequestId = crypto.randomUUID();
          const challengeToken = await buildSignedToken(
            buildConfirmationChallengePayload({
              confirmationRequestId,
              request: evaluation.normalizedRequest,
              executionMode: evaluation.executionMode,
              issuedAtMs: confirmationIssuedAtMs,
              expiresAtMs,
            }),
          );
          confirmation = {
            confirmationRequestId,
            challengeToken,
            prompt: buildConfirmationPrompt({
              request: evaluation.normalizedRequest,
              reason: evaluation.reason,
            }),
            summary: buildConfirmationSummary({
              request: evaluation.normalizedRequest,
              reason: evaluation.reason,
            }),
            expiresAtMs,
            executionMode: evaluation.executionMode,
          };
          pendingConfirmations.set(confirmationRequestId, {
            confirmationRequestId,
            challengeToken,
            expiresAtMs,
            request: evaluation.normalizedRequest,
            level: evaluation.level,
            decision: evaluation.decision,
            executionMode: evaluation.executionMode,
            reason: evaluation.reason,
            matchedRuleId: evaluation.matchedRuleId,
            scopeTokenTtlMs:
              typeof evaluation.normalizedRequest.ttlMs === "number" &&
              Number.isFinite(evaluation.normalizedRequest.ttlMs) &&
              evaluation.normalizedRequest.ttlMs > 0
                ? evaluation.normalizedRequest.ttlMs
                : 5_000,
            classification: evaluation.classification,
            evidence: {
              backend: "openclaw-trusted-backend",
              adaptor: adaptor.adaptor,
              platform: adaptor.platform,
              proofPath: adaptor.proofPath,
              proof: adaptorResult.proof,
            },
          });
        }
        const responsePayload = {
          ...evaluation,
          scopeToken:
            evaluation.allow && evaluation.executionMode !== "ree-direct"
              ? await buildScopeToken(evaluation.normalizedRequest)
              : undefined,
          confirmation,
          evidence: {
            backend: "openclaw-trusted-backend",
            adaptor: adaptor.adaptor,
            platform: adaptor.platform,
            proofPath: adaptor.proofPath,
            proof: adaptorResult.proof,
          },
        };
        await appendJsonl(eventsFile, {
          event: "authorize",
          ts: Date.now(),
          adaptor: adaptor.adaptor,
          platform: adaptor.platform,
          request,
          response: responsePayload,
        });
        const response = json(200, responsePayload);
        res.writeHead(response.statusCode, response.headers);
        res.end(response.body);
        return;
      }

      if (method === "POST" && url.pathname === "/v1/trusted/confirm") {
        const request = await readJsonBody(req);
        const confirmationRequestId = String(request.confirmationRequestId || "").trim();
        const challengeToken = String(request.challengeToken || "").trim();
        const operatorId = String(request.operatorId || "").trim() || "operator";
        const operatorDecision = String(request.decision || "")
          .trim()
          .toLowerCase();
        const now = Date.now();
        const pending = pendingConfirmations.get(confirmationRequestId);

        let responsePayload;
        if (!pending || pending.expiresAtMs < now) {
          if (pending) {
            pendingConfirmations.delete(confirmationRequestId);
          }
          responsePayload = {
            ok: false,
            confirmationRequestId,
            status: "expired",
            decision: "ddeny",
            level: pending?.level ?? "L3",
            executionMode: pending?.executionMode ?? "ree-constrained",
            reason: "trusted confirmation expired",
            matchedRuleId: pending?.matchedRuleId ?? "confirm.expired",
            normalizedRequest: pending?.request ?? null,
            confirmedAtMs: now,
            operatorId,
          };
        } else if (
          !challengeToken ||
          !pending.challengeToken ||
          !timingSafeTextEqual(challengeToken, pending.challengeToken)
        ) {
          responsePayload = {
            ok: false,
            confirmationRequestId,
            status: "denied",
            decision: "ddeny",
            level: pending.level,
            executionMode: pending.executionMode,
            reason: "trusted confirmation challenge mismatch",
            matchedRuleId: "confirm.challenge-mismatch",
            normalizedRequest: pending.request,
            confirmedAtMs: now,
            operatorId,
          };
        } else if (operatorDecision !== "approve") {
          pendingConfirmations.delete(confirmationRequestId);
          responsePayload = {
            ok: false,
            confirmationRequestId,
            status: "denied",
            decision: "ddeny",
            level: pending.level,
            executionMode: pending.executionMode,
            reason: String(request.reason || "").trim() || "trusted confirmation denied",
            matchedRuleId: "confirm.operator-deny",
            normalizedRequest: pending.request,
            confirmedAtMs: now,
            operatorId,
            evidence: pending.evidence,
          };
        } else {
          pendingConfirmations.delete(confirmationRequestId);
          responsePayload = {
            ok: true,
            confirmationRequestId,
            status: "approved",
            decision: decisionForConfirmedExecutionMode(pending.executionMode),
            level: pending.level,
            executionMode: pending.executionMode,
            reason: pending.reason,
            matchedRuleId: pending.matchedRuleId,
            normalizedRequest: pending.request,
            confirmedAtMs: now,
            operatorId,
            scopeToken:
              pending.executionMode === "ree-direct"
                ? undefined
                : await buildScopeToken(pending.request, {
                    issuedAtMs: now,
                    ttlMs: pending.scopeTokenTtlMs,
                  }),
            evidence: pending.evidence,
          };
        }

        await appendJsonl(eventsFile, {
          event: "confirm",
          ts: now,
          adaptor: adaptor.adaptor,
          platform: adaptor.platform,
          request,
          response: responsePayload,
        });
        const response = json(200, responsePayload);
        res.writeHead(response.statusCode, response.headers);
        res.end(response.body);
        return;
      }

      if (method === "POST" && url.pathname === "/v1/trusted/complete") {
        const request = await readJsonBody(req);
        const adaptorResult = await adaptor.complete({ request });
        await appendJsonl(eventsFile, {
          event: "complete",
          ts: Date.now(),
          adaptor: adaptor.adaptor,
          platform: adaptor.platform,
          request,
          proof: adaptorResult.proof,
        });
        const response = json(200, {
          ok: true,
          adaptor: adaptor.adaptor,
          platform: adaptor.platform,
          proof: adaptorResult.proof,
        });
        res.writeHead(response.statusCode, response.headers);
        res.end(response.body);
        return;
      }

      const response = json(404, { error: "not_found" });
      res.writeHead(response.statusCode, response.headers);
      res.end(response.body);
    } catch (error) {
      const response = json(500, {
        error: "internal_error",
        message: error instanceof Error ? error.message : String(error),
      });
      res.writeHead(response.statusCode, response.headers);
      res.end(response.body);
    }
  });

  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => resolve(undefined));
  });

  console.log(`openclaw-trusted-backend listening on http://${host}:${port}`);

  const shutdown = async () => {
    await new Promise((resolve) => server.close(() => resolve(undefined)));
    process.exit(0);
  };

  process.on("SIGINT", () => void shutdown());
  process.on("SIGTERM", () => void shutdown());
}

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  void startTrustedBackendServer().catch((error) => {
    console.error(error instanceof Error ? error.stack || error.message : String(error));
    process.exit(1);
  });
}
