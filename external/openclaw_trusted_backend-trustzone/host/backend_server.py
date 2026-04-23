#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


DEFAULT_BIND = "0.0.0.0"
DEFAULT_PORT = 19090
DEFAULT_SCOPE_TOKEN_TTL_MS = 15_000
DEFAULT_CONFIRMATION_TTL_MS = 5 * 60 * 1000
DEFAULT_CA_BINARY = "./optee_example_openclaw_trusted_backend"
DEFAULT_ADAPTOR = "optee-ree-backend"
DEFAULT_BACKEND_NAME = "optee-openclaw-trusted-backend-example"


def now_ms() -> int:
    return int(time.time() * 1000)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def coerce_int(value: Any, fallback: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def build_fallback_classification(reason: str, matched_rule_id: str, level: str) -> dict[str, Any]:
    destructive = level == "L3"
    export = matched_rule_id.endswith("exportish")
    return {
        "actionRisk": {
            "level": level,
            "reason": reason,
            "matchedRuleId": matched_rule_id,
        },
        "objectRisk": {
            "level": "L0" if not destructive else "L3",
            "reason": "ordinary workspace target" if not destructive else "protected target",
            "matchedRuleId": matched_rule_id,
            "classification": "ordinary" if not destructive else "critical",
        },
        "contextRisk": {
            "level": "L0",
            "reason": "OP-TEE REE proxy example",
            "matchedRuleId": "context.default",
            "factors": {},
        },
        "effectRisk": {
            "level": level,
            "reason": reason,
            "matchedRuleId": matched_rule_id,
            "factors": {},
        },
        "contextFlags": {
            "destructive": destructive,
            "export": export,
            "multi_step": False,
            "outside_workspace": False,
            "protected_path": destructive,
            "remote_target": False,
            "shell_wrapper": False,
            "task_mismatch": False,
            "user_absent": False,
        },
        "effectFlags": {
            "destructive": destructive,
            "export": export,
            "multi_step": False,
            "outside_workspace": False,
            "protected_path": destructive,
            "remote_target": False,
            "shell_wrapper": False,
            "task_mismatch": False,
            "user_absent": False,
        },
        "finalRiskLevel": level,
        "decision": "dia",
        "reason": reason,
        "matchedRuleId": matched_rule_id,
    }


def ensure_required_string(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"missing or invalid field: {key}")
    return value.strip()


@dataclass
class PendingConfirmation:
    request: dict[str, Any]
    level: str
    execution_mode: str
    reason: str
    matched_rule_id: str
    evidence: dict[str, Any]
    challenge_token: str
    expires_at_ms: int


class TrustedBackendShim:
    def __init__(
        self,
        *,
        ca_binary: str,
        verify_mode: str,
        hmac_key: str | None,
        scope_token_ttl_ms: int,
        confirmation_ttl_ms: int,
    ) -> None:
        self.ca_binary = ca_binary
        self.verify_mode = verify_mode
        self.hmac_key = hmac_key
        self.scope_token_ttl_ms = scope_token_ttl_ms
        self.confirmation_ttl_ms = confirmation_ttl_ms
        self.pending_confirmations: dict[str, PendingConfirmation] = {}

    def run_ca(self, *args: str) -> dict[str, Any]:
        command = [self.ca_binary, *args]
        completed = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
        )
        stdout = completed.stdout.strip()
        if not stdout:
            raise RuntimeError(f"empty response from CA command: {' '.join(command)}")
        return json.loads(stdout)

    def mint_scope_token(self, request: dict[str, Any], *, issued_at_ms: int | None = None) -> str:
        issued = issued_at_ms if issued_at_ms is not None else now_ms()
        ttl_ms = coerce_int(request.get("ttlMs"), self.scope_token_ttl_ms)
        payload = {
            "version": 1,
            "reqId": request["reqId"],
            "sid": request["sid"],
            "action": request["action"],
            "object": request["object"],
            "scope": copy.deepcopy(request.get("scope", {})),
            "normalizedScopeDigest": request["normalizedScopeDigest"],
            "issuedAtMs": issued,
            "expiresAtMs": issued + max(ttl_ms, 1000),
        }
        payload_b64 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        if self.verify_mode == "none":
            signature = b"none"
        elif self.verify_mode == "hmac-sha256":
            if not self.hmac_key:
                raise RuntimeError("verify mode hmac-sha256 requires OPTEE_TRUSTED_HMAC_KEY")
            signature = hmac.new(
                self.hmac_key.encode("utf-8"),
                payload_b64.encode("utf-8"),
                hashlib.sha256,
            ).digest()
        else:
            raise RuntimeError(
                "unsupported verify mode for example server; use none or hmac-sha256"
            )
        return f"{payload_b64}.{b64url_encode(signature)}"

    def build_backend_evidence(
        self,
        ca_payload: dict[str, Any],
        *,
        matched_rule_id: str | None = None,
    ) -> dict[str, Any]:
        evidence = ca_payload.get("evidence")
        if isinstance(evidence, dict):
            return copy.deepcopy(evidence)
        return {
            "backend": DEFAULT_BACKEND_NAME,
            "adaptor": DEFAULT_ADAPTOR,
            "platform": "trustzone",
            "proofPath": "ree-proxy",
            "proof": {
                "platform": "trustzone",
                "adaptor": DEFAULT_ADAPTOR,
                "proofPath": "ree-proxy",
                "teeCall": "TEEC_InvokeCommand",
                "matchedRuleId": matched_rule_id or "optee.example.unknown",
                "worldId": "optee-secure-world",
                "measurementSha256": "sha256:optee-example",
                "nonceBound": True,
            },
        }

    def healthz(self) -> tuple[int, dict[str, Any]]:
        payload = self.run_ca("healthz")
        payload["mode"] = self.verify_mode
        return HTTPStatus.OK, payload

    def guest(self) -> tuple[int, dict[str, Any]]:
        payload = self.run_ca("guest")
        return HTTPStatus.OK, payload

    def authorize(self, request: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        req_id = ensure_required_string(request, "reqId")
        sid = ensure_required_string(request, "sid")
        tool_name = ensure_required_string(request, "toolName")
        action = ensure_required_string(request, "action")
        obj = ensure_required_string(request, "object")
        level = ensure_required_string(request, "level")
        seq = coerce_int(request.get("seq"), 1)
        ttl_ms = coerce_int(request.get("ttlMs"), self.scope_token_ttl_ms)

        ca_payload = self.run_ca(
            "authorize",
            "--req-id",
            req_id,
            "--sid",
            sid,
            "--tool-name",
            tool_name,
            "--action",
            action,
            "--object",
            obj,
            "--level",
            level,
            "--seq",
            str(seq),
            "--ttl-ms",
            str(ttl_ms),
        )

        matched_rule_id = str(ca_payload.get("matchedRuleId") or "optee.example.unknown")
        classification = ca_payload.get("classification")
        if not isinstance(classification, dict):
            classification = build_fallback_classification(
                str(ca_payload.get("reason") or "OP-TEE example decision"),
                matched_rule_id,
                str(ca_payload.get("level") or level),
            )

        normalized_request = copy.deepcopy(request)
        evidence = self.build_backend_evidence(ca_payload, matched_rule_id=matched_rule_id)
        response: dict[str, Any] = {
            "allow": bool(ca_payload.get("allow")),
            "decision": ca_payload.get("decision", "ddeny"),
            "level": ca_payload.get("level", level),
            "executionMode": ca_payload.get("executionMode", "ree-constrained"),
            "reason": ca_payload.get("reason", "OP-TEE example decision"),
            "matchedRuleId": matched_rule_id,
            "normalizedRequest": normalized_request,
            "classification": classification,
            "scopeToken": None,
            "confirmation": None,
            "evidence": evidence,
        }

        if response["allow"] and response["executionMode"] != "ree-direct":
            response["scopeToken"] = self.mint_scope_token(normalized_request)

        confirmation = ca_payload.get("confirmation")
        if isinstance(confirmation, dict):
            confirmation_request_id = ensure_required_string(
                confirmation, "confirmationRequestId"
            )
            challenge_token = ensure_required_string(confirmation, "challengeToken")
            expires_at_ms = now_ms() + self.confirmation_ttl_ms
            self.pending_confirmations[confirmation_request_id] = PendingConfirmation(
                request=normalized_request,
                level=str(response["level"]),
                execution_mode=str(response["executionMode"]),
                reason=str(response["reason"]),
                matched_rule_id=matched_rule_id,
                evidence=evidence,
                challenge_token=challenge_token,
                expires_at_ms=expires_at_ms,
            )
            response["confirmation"] = {
                "confirmationRequestId": confirmation_request_id,
                "challengeToken": challenge_token,
                "prompt": confirmation.get("prompt", "OP-TEE example approval required"),
                "summary": confirmation.get("summary", response["reason"]),
                "expiresAtMs": expires_at_ms,
                "executionMode": response["executionMode"],
            }

        return HTTPStatus.OK, response

    def confirm(self, request: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        confirmation_request_id = ensure_required_string(request, "confirmationRequestId")
        challenge_token = ensure_required_string(request, "challengeToken")
        operator_id = ensure_required_string(request, "operatorId")
        decision = ensure_required_string(request, "decision")

        pending = self.pending_confirmations.get(confirmation_request_id)
        if pending is None:
            return HTTPStatus.OK, {
                "ok": False,
                "confirmationRequestId": confirmation_request_id,
                "status": "expired",
                "decision": "ddeny",
                "level": "L3",
                "executionMode": "ree-constrained",
                "reason": "trusted confirmation expired",
                "matchedRuleId": "confirm.expired",
                "normalizedRequest": None,
                "confirmedAtMs": now_ms(),
                "operatorId": operator_id,
            }

        if pending.expires_at_ms < now_ms():
            del self.pending_confirmations[confirmation_request_id]
            return HTTPStatus.OK, {
                "ok": False,
                "confirmationRequestId": confirmation_request_id,
                "status": "expired",
                "decision": "ddeny",
                "level": pending.level,
                "executionMode": pending.execution_mode,
                "reason": "trusted confirmation expired",
                "matchedRuleId": "confirm.expired",
                "normalizedRequest": pending.request,
                "confirmedAtMs": now_ms(),
                "operatorId": operator_id,
                "evidence": pending.evidence,
            }

        ca_payload = self.run_ca(
            "confirm",
            "--confirmation-request-id",
            confirmation_request_id,
            "--challenge-token",
            challenge_token,
            "--operator-id",
            operator_id,
            "--decision",
            decision,
        )

        approved = bool(ca_payload.get("ok")) and ca_payload.get("status") == "approved"
        response: dict[str, Any] = {
            "ok": bool(ca_payload.get("ok")),
            "confirmationRequestId": confirmation_request_id,
            "status": ca_payload.get("status", "denied"),
            "decision": ca_payload.get("decision", "ddeny"),
            "level": ca_payload.get("level", pending.level),
            "executionMode": ca_payload.get("executionMode", pending.execution_mode),
            "reason": ca_payload.get("reason", pending.reason),
            "matchedRuleId": ca_payload.get("matchedRuleId", pending.matched_rule_id),
            "normalizedRequest": pending.request,
            "confirmedAtMs": now_ms(),
            "operatorId": operator_id,
            "scopeToken": self.mint_scope_token(pending.request) if approved else None,
            "evidence": pending.evidence,
        }

        if response["status"] in {"approved", "denied", "expired"}:
            self.pending_confirmations.pop(confirmation_request_id, None)

        return HTTPStatus.OK, response

    def complete(self, request: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        req_id = ensure_required_string(request, "reqId")
        sid = ensure_required_string(request, "sid")
        tool_name = ensure_required_string(request, "toolName")
        action = ensure_required_string(request, "action")
        obj = ensure_required_string(request, "object")
        status = ensure_required_string(request, "status")
        result_digest = ensure_required_string(request, "resultDigest")

        ca_payload = self.run_ca(
            "complete",
            "--req-id",
            req_id,
            "--sid",
            sid,
            "--tool-name",
            tool_name,
            "--action",
            action,
            "--object",
            obj,
            "--status",
            status,
            "--result-digest",
            result_digest,
        )
        return HTTPStatus.OK, ca_payload


class RequestHandler(BaseHTTPRequestHandler):
    server_version = "OpenClawOPTEEExample/1.0"

    @property
    def shim(self) -> TrustedBackendShim:
        return self.server.shim  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write("%s - - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), fmt % args))

    def send_json(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def read_json_body(self) -> dict[str, Any]:
        content_length = coerce_int(self.headers.get("Content-Length"), 0)
        raw = self.rfile.read(content_length) if content_length > 0 else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid json body: {exc}") from exc
        if not isinstance(payload, dict):
            raise ValueError("expected a JSON object")
        return payload

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/healthz":
                status, payload = self.shim.healthz()
            elif parsed.path == "/v1/trusted/guest":
                status, payload = self.shim.guest()
            else:
                status, payload = HTTPStatus.NOT_FOUND, {"error": "not_found"}
        except subprocess.CalledProcessError as exc:
            status, payload = HTTPStatus.INTERNAL_SERVER_ERROR, {
                "error": "ca_invocation_failed",
                "message": exc.stderr.strip() if exc.stderr else str(exc),
            }
        except Exception as exc:  # noqa: BLE001
            status, payload = HTTPStatus.INTERNAL_SERVER_ERROR, {
                "error": "internal_error",
                "message": str(exc),
            }
        self.send_json(status, payload)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        try:
            body = self.read_json_body()
            if parsed.path == "/v1/trusted/authorize":
                status, payload = self.shim.authorize(body)
            elif parsed.path == "/v1/trusted/confirm":
                status, payload = self.shim.confirm(body)
            elif parsed.path == "/v1/trusted/complete":
                status, payload = self.shim.complete(body)
            else:
                status, payload = HTTPStatus.NOT_FOUND, {"error": "not_found"}
        except ValueError as exc:
            status, payload = HTTPStatus.BAD_REQUEST, {"error": "bad_request", "message": str(exc)}
        except subprocess.CalledProcessError as exc:
            status, payload = HTTPStatus.INTERNAL_SERVER_ERROR, {
                "error": "ca_invocation_failed",
                "message": exc.stderr.strip() if exc.stderr else str(exc),
            }
        except Exception as exc:  # noqa: BLE001
            status, payload = HTTPStatus.INTERNAL_SERVER_ERROR, {
                "error": "internal_error",
                "message": str(exc),
            }
        self.send_json(status, payload)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="OpenClaw trusted backend OP-TEE example HTTP shim",
    )
    parser.add_argument(
        "--bind",
        default=os.environ.get("OPTEE_BACKEND_BIND", DEFAULT_BIND),
        help="bind address",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=coerce_int(os.environ.get("OPTEE_BACKEND_PORT"), DEFAULT_PORT),
        help="listen port",
    )
    parser.add_argument(
        "--ca-binary",
        default=os.environ.get("OPTEE_BACKEND_CA_BINARY", DEFAULT_CA_BINARY),
        help="path to the compiled REE CA binary",
    )
    parser.add_argument(
        "--verify-mode",
        default=os.environ.get("OPTEE_TRUSTED_VERIFY_MODE", "none"),
        choices=["none", "hmac-sha256"],
        help="scope token verification mode exposed to OpenClaw",
    )
    parser.add_argument(
        "--hmac-key",
        default=os.environ.get("OPTEE_TRUSTED_HMAC_KEY"),
        help="shared HMAC key when verify-mode=hmac-sha256",
    )
    parser.add_argument(
        "--scope-token-ttl-ms",
        type=int,
        default=coerce_int(
            os.environ.get("OPTEE_SCOPE_TOKEN_TTL_MS"), DEFAULT_SCOPE_TOKEN_TTL_MS
        ),
        help="scope token TTL in milliseconds",
    )
    parser.add_argument(
        "--confirmation-ttl-ms",
        type=int,
        default=coerce_int(
            os.environ.get("OPTEE_CONFIRMATION_TTL_MS"), DEFAULT_CONFIRMATION_TTL_MS
        ),
        help="pending confirmation TTL in milliseconds",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ca_binary = Path(args.ca_binary).expanduser().resolve()
    if not ca_binary.exists():
        print(f"CA binary not found: {ca_binary}", file=sys.stderr)
        return 1

    shim = TrustedBackendShim(
        ca_binary=str(ca_binary),
        verify_mode=args.verify_mode,
        hmac_key=args.hmac_key,
        scope_token_ttl_ms=args.scope_token_ttl_ms,
        confirmation_ttl_ms=args.confirmation_ttl_ms,
    )
    server = ThreadingHTTPServer((args.bind, args.port), RequestHandler)
    server.shim = shim  # type: ignore[attr-defined]

    print(
        f"openclaw-optee-backend listening on http://{args.bind}:{args.port} "
        f"(ca={ca_binary}, verify_mode={args.verify_mode})"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
