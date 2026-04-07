# Trusted Isolation Design

## Goal

This implementation aligns OpenClaw's trusted isolation path with the paper's operation-centric model:

1. request canonicalization
2. trusted authorization
3. scope-bound execution
4. trusted evidence generation

The design keeps OpenClaw-side changes minimal and moves trusted semantics into separable trusted-layer components.

## Minimal OpenClaw Patches

OpenClaw now keeps only these integration points in its main execution path:

- `src/agents/pi-tools.before-tool-call.ts`
  - execution gate hook
  - calls `enforceTrustedIsolationBeforeToolCall(...)`
- `src/security/trusted-isolation/client.ts`
  - trusted authorize / complete client
  - uses direct `http/https` RPC instead of ambient global `fetch`
- `src/agents/cli-runner/execute.ts`
  - CLI backend execution gate
  - forwards Codex `command_execution` JSONL events into trusted-layer authorize / complete flow
- `src/agents/bash-tools.exec.ts`
  - constrained executor hook
  - enforces token-bound exec scope before the shell command runs
- `src/agents/pi-tools.read.ts`
  - path-scope enforcement hook for read/write/edit surfaces
- `src/agents/apply-patch.ts`
  - patch-scope enforcement hook
- `src/agents/pi-embedded-subscribe.handlers.tools.ts`
  - completion/finalization hook
- `src/security/trusted-isolation/runtime.ts`
  - fail-closed orchestration
  - authorize / deny / complete / backend-error evidence glue
- `src/security/trusted-isolation/config.ts`
  - config resolution only

## Trusted-Layer Components

Trusted-layer semantics now live behind a separate module boundary:

- `src/security/trusted-layer/types.ts`
  - unified request / response / token / evidence schema
- `src/security/trusted-layer/request.ts`
  - canonical trusted operation request builder
- `src/security/trusted-layer/scope.ts`
  - scope token verification and constrained exec/path enforcement
- `src/security/trusted-layer/evidence.ts`
  - hash-chained evidence writer and validator
- `src/security/trusted-layer/codex-cli.ts`
  - Codex CLI event bridge
  - unwraps Codex's outer `/bin/bash -lc ...` transport shell
  - maps observed `command_execution` items to canonical trusted exec requests
- `src/security/trusted-layer/errors.ts`
  - stable fail-closed error taxonomy
- `src/security/trusted-layer/state.ts`
  - pending authorize -> complete correlation
- `external/openclaw-trusted-backend/policy.mjs`
  - rule-driven risk engine
- `external/openclaw-trusted-backend/adaptors.mjs`
  - cross-platform adaptor layer
- `external/openclaw-trusted-backend/server.mjs`
  - standalone trusted authorize / complete API
- `scripts/scaffold-trusted-backend-standalone.mjs`
  - deploys the canonical external backend tree into a runtime directory

The legacy `src/security/trusted-isolation/{types,digest,errors,request,evidence,scope,state}.ts` files are now compatibility re-exports pointing at `src/security/trusted-layer/*`.

## Canonical Trusted Operation Request

The canonical request is the single source of truth for authorize, token binding, complete, and evidence:

```ts
type TrustedOperationRequest = {
  version: 1;
  reqId: string;
  sid: string;
  seq: number;
  ttlMs: number;
  issuedAtMs: number;
  toolName: string;
  action: "read" | "modify" | "delete" | "exec" | "export" | "network" | "unknown";
  object: string;
  scope: TrustedIsolationScope;
  context: TrustedIsolationContext;
  level: "L0" | "L1" | "L2" | "L3";
  normalizedScopeDigest: string;
  requestDigest: string;
};
```

For `exec`, the canonical scope currently binds:

- raw command
- normalized command binary
- exact args
- cwd
- env subset

For shell compound commands such as `if ...; then ...; fi`, OpenClaw now
switches the exec scope to `matchMode: "shell-exact"` and binds the exact raw
shell text plus execution context instead of trying to derive a misleading argv
shape from shell syntax tokens.

This eliminates the earlier split-brain behavior where authorize used one shape while evidence re-derived another one.

## Request Flow

### Baseline Mode

- `tools.trustedIsolation.enabled = false`
- OpenClaw bypasses the trusted path
- normal REE execution continues

### Protected Mode

1. OpenClaw extracts a canonical operation request from the tool call.
2. The request is sent to `/v1/trusted/authorize`.
3. The backend returns:
   - normalized request
   - action risk
   - object risk
   - context/effect flags
   - final risk level
   - decision
   - matched rule id
   - scope token if allowed
4. OpenClaw injects the returned scope envelope into the tool args.
5. The constrained executor verifies that the actual exec matches the authorized scope.
6. OpenClaw sends `/v1/trusted/complete`.
7. OpenClaw appends hash-chained evidence locally.

### Protected CLI Backend Mode

For `codex-cli`, OpenClaw now reuses the same trusted-layer semantics through
Codex's JSONL event stream:

1. `src/agents/cli-runner/execute.ts` subscribes to streamed Codex JSONL.
2. Each `item.started` with `item.type = "command_execution"` is normalized
   into a canonical trusted `exec` request.
3. OpenClaw performs trusted authorize against the observed command.
4. The returned scope token is verified against the observed command event.
5. `item.completed` is finalized through the same trusted complete + evidence path.

This preserves the request -> decision -> execution -> evidence chain for
CLI-backed Codex runs without moving the risk engine into OpenClaw core.

## Fail-Closed Semantics

For `forceTrustedActions: ["exec"]`, the implementation rejects execution when any of the following occurs:

- backend unreachable
- authorize timeout
- malformed authorize JSON
- missing scope token
- token signature/HMAC verification failure
- token expiry
- scope mismatch

Stable error codes:

- `trusted_backend_unavailable`
- `trusted_authorization_timeout`
- `trusted_authorization_invalid_response`
- `trusted_authorization_missing_scope_token`
- `trusted_authorization_rejected`
- `trusted_scope_violation`
- `trusted_scope_token_verification_failed`
- `trusted_scope_token_expired`
- `trusted_complete_timeout`
- `trusted_complete_invalid_response`
- `trusted_evidence_write_failure`

`complete` failures do not retroactively re-run the exec path, but they do emit `backend_error` evidence instead of silently disappearing.

## Rule-Driven Policy Engine

The standalone backend implements a first paper-oriented exec policy engine:

- risk levels: `L0`, `L1`, `L2`, `L3`
- decisions: `dree`, `dia`, `die`, `duc`, `ddeny`
- dimensions:
  - action sensitivity
  - object criticality
  - context flags
  - effect flags

Current exec rules include:

- low-risk allowlist commands: `echo`, `ls`, `pwd`, `printf`, `sort`, `head`, `tail`, `wc`, `uniq`, `cut`, `tr`, `true`, `false`
- medium read/modify commands: `cat`, `grep`, `find`, `cp`, `mv`, `mkdir`, `tar`, `zip`, `chmod`, `sed`, `awk`
- high-risk patterns:
  - `curl ... | sh`
  - `wget ... | sh`
  - `bash -c`
  - `sh -c`
  - `python -c`
  - `node -e`
  - `perl -e`
  - `rm -rf`
  - protected-path permission mutation

The backend returns `matchedRuleId` and classification data in authorize responses and evidence.

## Evidence Semantics

Default evidence path:

- `${OPENCLAW_STATE_DIR}/security/trusted-evidence.jsonl`

Evidence events:

- `authorize`
- `complete`
- `deny`
- `violation`
- `backend_error`

Each record includes:

- `reqId`
- `sid`
- `toolName`
- `action`
- `object`
- `normalizedScopeDigest`
- `requestDigest`
- `decision`
- `status`
- `durationMs` when applicable
- `prevHash`
- `entryHash`

Backend-side event records use the same chained model. The standalone trusted
backend restores the last persisted `entryHash` from its JSONL event log on
startup before appending new records, so the backend-side chain remains
continuous across process restarts instead of silently restarting from an empty
`prevHash`.

The validator checks:

- `authorize` / `complete` pairing
- `authorize` / `violation` consistency
- hash continuity
- action/object/scope digest/request digest consistency per `reqId`

## Cross-Platform Structure

OpenClaw uses a single trusted API:

- `POST /v1/trusted/authorize`
- `POST /v1/trusted/complete`

Backend adaptors:

- `local-tdx`
- `trustzone-remote-backend`
- `keystone-remote-backend`

OpenClaw does not branch on TEE internals. Platform-specific behavior is encapsulated by the sidecar backend adaptor.

## How This Maps To The Paper Architecture

- OpenClaw Execution Gate
  - `src/agents/pi-tools.before-tool-call.ts`
  - `src/security/trusted-isolation/runtime.ts`
  - `src/agents/cli-runner/execute.ts`
- Trusted Operation Request
  - `src/security/trusted-layer/request.ts`
  - `src/security/trusted-layer/types.ts`
  - `src/security/trusted-layer/codex-cli.ts`
- Trusted Operation Plane
  - `external/openclaw-trusted-backend/server.mjs`
  - `external/openclaw-trusted-backend/policy.mjs`
  - `external/openclaw-trusted-backend/adaptors.mjs`
- Constrained Executor
  - `src/agents/bash-tools.exec.ts`
  - `src/security/trusted-layer/scope.ts`
- Trusted Audit / Evidence
  - `src/security/trusted-layer/evidence.ts`
  - `scripts/trusted-evidence-check.ts`
- User Notification / Confirmation
  - `duc` is returned as `confirmation_required`
  - interactive confirmation UI is not implemented yet
  - current behavior is fail-closed: the action does not continue

## Current Limits

- `exec` is the fully hardened path today; read/write/edit/apply_patch hooks are wired, but the paper-grade validation focus is still `exec`
- `duc` currently stops instead of routing to a user confirmation channel
- `ed25519` is supported by the backend and verifier path, but the default smoke path uses `hmac-sha256`
- the TrustZone and Keystone adaptors are minimal proof-path adaptors today; the unified API is stable, but their secure-world/enclave transports remain placeholders for platform-specific implementations
