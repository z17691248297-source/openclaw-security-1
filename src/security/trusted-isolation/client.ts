import http from "node:http";
import https from "node:https";
import {
  createTrustedAuthorizationInvalidResponseError,
  createTrustedAuthorizationTimeoutError,
  createTrustedBackendUnavailableError,
  createTrustedConfirmationInvalidResponseError,
  createTrustedConfirmationTimeoutError,
  createTrustedCompleteInvalidResponseError,
  createTrustedCompleteTimeoutError,
} from "./errors.js";
import type {
  TrustedAuthorizeRequest,
  TrustedAuthorizeResponse,
  TrustedConfirmRequest,
  TrustedConfirmResponse,
  TrustedCompleteRequest,
} from "./types.js";

function joinUrl(base: string, path: string): string {
  const trimmedBase = base.replace(/\/+$/, "");
  const trimmedPath = path.startsWith("/") ? path : `/${path}`;
  return `${trimmedBase}${trimmedPath}`;
}

async function postJson<TResponse>(params: {
  url: string;
  body: unknown;
  timeoutMs: number;
  phase: "authorize" | "complete" | "confirm";
}): Promise<TResponse> {
  const url = new URL(params.url);
  const body = JSON.stringify(params.body);
  const transport = url.protocol === "https:" ? https : http;
  const { statusCode, text } = await new Promise<{
    statusCode: number;
    text: string;
  }>((resolve, reject) => {
    let timedOut = false;
    const request = transport.request(
      url,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(body),
        },
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk) => {
          chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
        });
        response.on("end", () => {
          resolve({
            statusCode: response.statusCode ?? 0,
            text: Buffer.concat(chunks).toString("utf8"),
          });
        });
      },
    );

    request.on("error", (error) => {
      reject(
        timedOut
          ? params.phase === "authorize"
            ? createTrustedAuthorizationTimeoutError(error)
            : params.phase === "confirm"
              ? createTrustedConfirmationTimeoutError(error)
              : createTrustedCompleteTimeoutError(error)
          : createTrustedBackendUnavailableError(error),
      );
    });
    request.setTimeout(Math.max(500, params.timeoutMs), () => {
      timedOut = true;
      request.destroy(new Error("timeout"));
    });
    request.write(body);
    request.end();
  });

  if (statusCode < 200 || statusCode >= 300) {
    throw createTrustedBackendUnavailableError(new Error(`HTTP ${statusCode}`));
  }

  if (!text.trim()) {
    return {} as TResponse;
  }
  try {
    return JSON.parse(text) as TResponse;
  } catch (error) {
    throw params.phase === "authorize"
      ? createTrustedAuthorizationInvalidResponseError(error)
      : params.phase === "confirm"
        ? createTrustedConfirmationInvalidResponseError(error)
        : createTrustedCompleteInvalidResponseError(error);
  }
}

export async function sendTrustedAuthorize(params: {
  backendBaseUrl: string;
  authorizePath: string;
  timeoutMs: number;
  request: TrustedAuthorizeRequest;
}): Promise<TrustedAuthorizeResponse> {
  return await postJson<TrustedAuthorizeResponse>({
    url: joinUrl(params.backendBaseUrl, params.authorizePath),
    body: params.request,
    timeoutMs: params.timeoutMs,
    phase: "authorize",
  });
}

export async function sendTrustedCompletion(params: {
  backendBaseUrl: string;
  completePath: string;
  timeoutMs: number;
  request: TrustedCompleteRequest;
}): Promise<void> {
  await postJson<Record<string, unknown>>({
    url: joinUrl(params.backendBaseUrl, params.completePath),
    body: params.request,
    timeoutMs: params.timeoutMs,
    phase: "complete",
  });
}

export async function sendTrustedConfirm(params: {
  backendBaseUrl: string;
  confirmPath: string;
  timeoutMs: number;
  request: TrustedConfirmRequest;
}): Promise<TrustedConfirmResponse> {
  return await postJson<TrustedConfirmResponse>({
    url: joinUrl(params.backendBaseUrl, params.confirmPath),
    body: params.request,
    timeoutMs: params.timeoutMs,
    phase: "confirm",
  });
}
