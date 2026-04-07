# Trusted Isolation Testing

## Prerequisites

- Node 22+
- repo dependencies installed
- bundled plugin runtime deps staging is optional for this flow
- use:

```bash
OPENCLAW_SKIP_BUNDLED_PLUGIN_RUNTIME_DEPS=1
```

## Local Smoke

Run the paper smoke script against a standalone local backend:

```bash
OPENCLAW_SKIP_BUNDLED_PLUGIN_RUNTIME_DEPS=1 \
node --import tsx scripts/trusted-isolation-paper-smoke.ts
```

Expected checks:

- allow case passes
- scope violation passes
- ttl-expired rejection passes
- fail-closed passes
- evidence consistency passes

## Guest Backend Smoke

Run the same OpenClaw-side smoke against a guest-hosted trusted backend:

```bash
OPENCLAW_SKIP_BUNDLED_PLUGIN_RUNTIME_DEPS=1 \
node --import tsx scripts/trusted-isolation-paper-smoke.ts \
  --backend-base-url http://<tdx-guest-ip>:19090
```

Use the same shared HMAC key on both sides for the first integration pass.

If the guest backend is already running with `verify.mode = ed25519`, pass the
exported guest public key as well:

```bash
OPENCLAW_SKIP_BUNDLED_PLUGIN_RUNTIME_DEPS=1 \
node --import tsx scripts/trusted-isolation-paper-smoke.ts \
  --backend-base-url http://<tdx-guest-ip>:19090 \
  --verify-mode ed25519 \
  --public-key-file /var/tmp/openclaw-tdx/ed25519-public.pem
```

That smoke confirms the OpenClaw host is talking to the TDX guest backend. It
does not yet prove quote-backed guest attestation.

To validate the host-side quote prerequisites before wiring a real guest
attestation command, run:

```bash
sudo scripts/tdx/check-attestation-host.sh --show-logs
```

If that check reports a libvirt/AppArmor AF_VSOCK blocker, or if the guest qemu
log shows `Failed to connect to '2:4050': Permission denied`, rerun the host
libvirt fix and then boot the TD again:

```bash
sudo scripts/tdx/configure-libvirt-tdx-host.sh --user "$USER"
```

If the guest qemu log instead shows `Failed to connect to '2:4050': No such device`,
recreate the TD with `scripts/tdx/run-canonical-tdvirsh.sh`; the wrapper
auto-detects whether the local `qgsd` listener should use AF_VSOCK CID `1` or `2`
and rewrites the generated TD XML.

When the host is ready and the guest can generate a quote successfully, you can
use the guest introspection endpoint to verify the backend sees real attestation
input:

```bash
curl "http://<tdx-guest-ip>:19090/v1/trusted/guest?attest=1"
```

If you prepared the guest with:

```bash
--attestation-command "/usr/local/bin/openclaw-tdx-attest"
```

that command now compiles a bundled `libtdx_attest` helper inside the guest and
returns a real quote-backed JSON payload through the backend's existing command
mode.

Expected result after the attestation command is wired:

- `guest.attestationMode` is `command`
- `guest.attestationReady` is `true`
- `attestation.quoteSha256` and `attestation.quoteBytes` are present

The canonical backend source now lives in `external/openclaw-trusted-backend/`. The
OpenClaw repo's smoke and bench scripts talk to that backend over the unified
HTTP API; they do not require an in-tree backend implementation.

## Codex CLI Runtime Smoke

To verify the real `codex-cli` execution path, run the gateway from the repo
working tree so the current trusted bridge code is active:

```bash
OPENCLAW_SKIP_BUNDLED_PLUGIN_RUNTIME_DEPS=1 \
pnpm openclaw gateway run --bind loopback --port 18789 --force
```

Then send a message through your configured channel such as WhatsApp:

```text
Run the shell command 'echo wa-trusted' exactly once, then reply with only the command output.
```

Expected result:

- the reply is `wa-trusted`
- the guest backend log records `authorize` + `complete`
- the host evidence file records paired `authorize` + `complete` entries
- `action`, `object`, and `matchedRuleId` are populated and not `unknown`

For a shell compound command such as:

```text
if [ -f HEARTBEAT.md ]; then sed -n '1,240p' HEARTBEAT.md; else echo '__NO_HEARTBEAT__'; fi
```

Expected result:

- `scope.exec.matchMode` is `shell-exact`
- backend `matchedRuleId` is `exec.action.shell-compound`
- object classification stays `object.ordinary.workspace`
- no phantom target such as `[` appears in object risk evidence

## Targeted Tests

Run the dedicated paper-oriented Vitest lane:

```bash
OPENCLAW_SKIP_BUNDLED_PLUGIN_RUNTIME_DEPS=1 \
corepack pnpm test -- src/security/trusted-isolation/tests
```

Covered cases:

- `allow_case.test.ts`
- `scope_violation_case.test.ts`
- `backend_unavailable_fail_closed.test.ts`
- `malformed_authorize_response.test.ts`
- `ttl_expired_case.test.ts`
- `evidence_consistency.test.ts`
- `src/security/trusted-layer/request.test.ts`
- `src/security/trusted-layer/scope.test.ts`
- `test/scripts/trusted-backend-policy.test.ts`
- `test/scripts/trusted-backend-server.test.ts`

Those additional tests cover:

- shell compound request canonicalization
- shell-exact token-bound exec enforcement
- compound-command policy classification
- backend event-log hash continuity across restart

## Evidence Validation

Check a produced evidence file:

```bash
node --import tsx scripts/trusted-evidence-check.ts \
  --file /path/to/trusted-evidence.jsonl
```

If `OPENCLAW_STATE_DIR` is set, the default file is:

```text
${OPENCLAW_STATE_DIR}/security/trusted-evidence.jsonl
```

## Benchmark

Run the minimal paper benchmark and emit CSV:

```bash
OPENCLAW_SKIP_BUNDLED_PLUGIN_RUNTIME_DEPS=1 \
node --import tsx scripts/trusted-isolation-paper-bench.ts \
  --runs 30 \
  --output trusted-isolation-bench.csv
```

To include a guest backend:

```bash
OPENCLAW_SKIP_BUNDLED_PLUGIN_RUNTIME_DEPS=1 \
node --import tsx scripts/trusted-isolation-paper-bench.ts \
  --runs 30 \
  --guest-backend-base-url http://<tdx-guest-ip>:19090 \
  --output trusted-isolation-bench.csv
```

CSV columns:

- `mode`
- `case`
- `run_id`
- `authorize_ms`
- `complete_ms`
- `e2e_ms`
- `result`

## Standalone Backend Scaffold

Generate a backend outside the OpenClaw tree:

```bash
node scripts/scaffold-trusted-backend-standalone.mjs \
  --target /path/to/openclaw-trusted-backend \
  --force
```

Then run it:

```bash
cd /path/to/openclaw-trusted-backend
TRUSTED_HMAC_KEY=replace-me TRUSTED_BACKEND_PORT=19090 node server.mjs
```

## Suggested `openclaw.json` Snippet

Use HMAC first:

```json
{
  "tools": {
    "trustedIsolation": {
      "enabled": true,
      "enforceFailClosed": true,
      "backendBaseUrl": "http://127.0.0.1:19090",
      "authorizePath": "/v1/trusted/authorize",
      "completePath": "/v1/trusted/complete",
      "requestTimeoutMs": 5000,
      "ttlMs": 5000,
      "verify": {
        "mode": "hmac-sha256",
        "hmacKey": "replace-with-a-shared-secret",
        "requireScopeToken": true
      },
      "forceTrustedActions": ["exec"]
    }
  }
}
```

Recommended follow-up for production:

- switch `verify.mode` to `ed25519`
- store the private key only in the trusted backend
- keep only the public key in OpenClaw
- then add mTLS and attestation on the host/guest path

Example `openclaw.json` host config after the cutover:

```json
{
  "tools": {
    "trustedIsolation": {
      "enabled": true,
      "enforceFailClosed": true,
      "backendBaseUrl": "http://<tdx-guest-ip>:19090",
      "authorizePath": "/v1/trusted/authorize",
      "completePath": "/v1/trusted/complete",
      "requestTimeoutMs": 5000,
      "ttlMs": 5000,
      "verify": {
        "mode": "ed25519",
        "publicKeyPem": "-----BEGIN PUBLIC KEY-----\\n<guest-public-key>\\n-----END PUBLIC KEY-----\\n",
        "requireScopeToken": true
      },
      "forceTrustedActions": ["exec"]
    }
  }
}
```

The host keeps only `publicKeyPem`. The guest keeps only the private key.

## Ed25519 Cutover

Generate the guest-side keypair:

```bash
sudo install -d -m 0750 /etc/openclaw-trusted-backend
sudo openssl genpkey -algorithm ED25519 \
  -out /etc/openclaw-trusted-backend/ed25519-private.pem
sudo openssl pkey \
  -in /etc/openclaw-trusted-backend/ed25519-private.pem \
  -pubout \
  -out /etc/openclaw-trusted-backend/ed25519-public.pem
sudo chmod 0600 /etc/openclaw-trusted-backend/ed25519-private.pem
sudo chmod 0644 /etc/openclaw-trusted-backend/ed25519-public.pem
```

Smoke against an `ed25519` backend:

```bash
OPENCLAW_SKIP_BUNDLED_PLUGIN_RUNTIME_DEPS=1 \
node --import tsx scripts/trusted-isolation-paper-smoke.ts \
  --backend-base-url http://<tdx-guest-ip>:19090 \
  --verify-mode ed25519 \
  --public-key-file /path/to/ed25519-public.pem
```

Benchmark against an `ed25519` backend:

```bash
OPENCLAW_SKIP_BUNDLED_PLUGIN_RUNTIME_DEPS=1 \
node --import tsx scripts/trusted-isolation-paper-bench.ts \
  --runs 30 \
  --guest-backend-base-url http://<tdx-guest-ip>:19090 \
  --verify-mode ed25519 \
  --public-key-file /path/to/ed25519-public.pem \
  --private-key-file /path/to/local-ed25519-private.pem \
  --output trusted-isolation-bench.csv
```

## Guest `systemd`

The standalone scaffold now includes:

- `openclaw-trusted-backend.service.example`
- `openclaw-trusted-backend.env.example`

Typical install flow on the guest:

```bash
sudo useradd --system --home /opt/openclaw-trusted-backend --shell /usr/sbin/nologin openclaw-trusted || true
sudo install -d -o openclaw-trusted -g openclaw-trusted /opt/openclaw-trusted-backend
sudo install -d -m 0750 /etc/openclaw-trusted-backend
sudo install -d -o openclaw-trusted -g openclaw-trusted /var/lib/openclaw-trusted-backend

node scripts/scaffold-trusted-backend-standalone.mjs \
  --target /opt/openclaw-trusted-backend \
  --force

sudo cp /opt/openclaw-trusted-backend/openclaw-trusted-backend.service.example \
  /etc/systemd/system/openclaw-trusted-backend.service
sudo cp /opt/openclaw-trusted-backend/openclaw-trusted-backend.env.example \
  /etc/openclaw-trusted-backend/openclaw-trusted-backend.env

sudo chown -R openclaw-trusted:openclaw-trusted /opt/openclaw-trusted-backend /var/lib/openclaw-trusted-backend
sudo systemctl daemon-reload
sudo systemctl enable --now openclaw-trusted-backend.service
sudo systemctl status openclaw-trusted-backend.service
```

## Host / Guest Deployment Topology

### Host

- OpenClaw gateway / agent runtime
- REE execution gate
- constrained executor
- local evidence file

### Guest

- trusted backend sidecar
- rule engine
- token minting
- authoritative authorize / complete semantics

### Example Start Commands

Host OpenClaw:

```bash
OPENCLAW_SKIP_BUNDLED_PLUGIN_RUNTIME_DEPS=1 \
openclaw gateway run --bind loopback --port 18789 --force
```

TDX guest trusted backend:

```bash
TRUSTED_BACKEND_HOST=0.0.0.0 \
TRUSTED_BACKEND_PORT=19090 \
TRUSTED_HMAC_KEY=replace-with-a-shared-secret \
TRUSTED_BACKEND_ADAPTOR=local-tdx \
node server.mjs
```

OpenClaw host config then points `tools.trustedIsolation.backendBaseUrl` at `http://<tdx-guest-ip>:19090`.

For a real Ubuntu TDX guest deployment based on Canonical's `tdx` tooling, see [TDX Guest](/install/tdx-guest).
