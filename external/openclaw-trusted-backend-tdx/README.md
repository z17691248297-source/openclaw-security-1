# OpenClaw Trusted Backend

This directory is a standalone trusted-layer sidecar for OpenClaw's trusted isolation flow.

## Files

- `server.mjs`: unified `/v1/trusted/authorize` and `/v1/trusted/complete` API
- `policy.mjs`: rule-driven exec policy engine
- `adaptors.mjs`: platform adaptors for `local-tdx`, `trustzone-remote-backend`, and `keystone-remote-backend`
- `tdx-guest.mjs`: TDX guest identity and attestation-source abstraction for `local-tdx`
- `policy.json`: optional override file merged with the built-in default policy
- `.env.example`: local development environment template
- `openclaw-trusted-backend.env.example`: systemd environment template
- `openclaw-trusted-backend.service.example`: systemd unit template

## Run

1. Copy `.env.example` to `.env` and adjust values.
2. Export the variables or source the file.
3. Start the backend:

```bash
node server.mjs
```

## Notes

- `local-tdx` is the primary end-to-end adaptor for Intel TDX deployments.
- `local-tdx` now supports guest identity + attestation-source inputs through env, file, or command mode.
- `trustzone-remote-backend` and `keystone-remote-backend` model the paper's REE-proxy pattern while preserving the unified API.
- The backend writes its own backend-side event log to `logs/trusted-backend-events.jsonl` by default.
- Production deployments typically point `TRUSTED_BACKEND_EVENTS_FILE` at `/var/lib/openclaw-trusted-backend/trusted-backend-events.jsonl`.
- Optional guest introspection endpoint: `GET /v1/trusted/guest` (`?attest=1` to force an attestation sample for `local-tdx`).
