This is a complete OP-TEE-style example for the OpenClaw trusted backend flow.

It is split into two REE-side layers plus one TA:

- the TA owns the example trusted decision logic
- the compiled REE CA invokes the TA with `TEEC_InvokeCommand`
- the REE HTTP shim exposes the OpenClaw trusted backend API and calls the CA
  binary

Layout:

- `host/main.c`: REE proxy CLI for direct TA testing
- `host/backend_server.py`: Python REE HTTP shim for OpenClaw
- `host/backend_server_c.c`: native C REE HTTP shim for OpenClaw
- `host/openclaw-trusted-backend-optee.env.example`: runtime env template
- `host/openclaw-trusted-backend-optee.service.example`: systemd unit template
- `ta/openclaw_trusted_backend_ta.c`: trusted decision logic
- `ta/include/openclaw_trusted_backend_ta.h`: shared UUID, command ids, and
  request/response structs

The HTTP shim exposes:

- `healthz`
- `guest`
- `authorize`
- `confirm`
- `complete`

Build the CA and TA:

```bash
make \
  TEEC_EXPORT=/path/to/optee_client/out/export \
  TA_DEV_KIT_DIR=/path/to/optee_os/out/arm/export-ta_arm64 \
  HOST_CROSS_COMPILE= \
  TA_CROSS_COMPILE=aarch64-linux-gnu-
```

Direct CA demo commands:

```bash
./host/optee_example_openclaw_trusted_backend healthz
./host/optee_example_openclaw_trusted_backend guest
./host/optee_example_openclaw_trusted_backend authorize \
  --req-id req-1 \
  --sid sid-1 \
  --tool-name exec \
  --action exec \
  --object "echo hello from optee"
./host/optee_example_openclaw_trusted_backend authorize \
  --req-id req-2 \
  --sid sid-1 \
  --tool-name exec \
  --action exec \
  --object "tar -czf workspace.tgz docs"
./host/optee_example_openclaw_trusted_backend confirm \
  --confirmation-request-id '<confirmation-id>' \
  --challenge-token '<challenge-token>' \
  --operator-id tester \
  --decision approve
./host/optee_example_openclaw_trusted_backend complete \
  --req-id req-1 \
  --sid sid-1 \
  --tool-name exec \
  --action exec \
  --object "echo hello from optee" \
  --status ok \
  --result-digest "sha256:example-result"
```

Run the native C HTTP shim:

```bash
./host/optee_example_openclaw_trusted_backend_server \
  --bind 0.0.0.0 \
  --port 19090 \
  --ca-binary ./host/optee_example_openclaw_trusted_backend \
  --verify-mode none
```

Or run the Python HTTP shim:

```bash
python3 ./host/backend_server.py \
  --bind 0.0.0.0 \
  --port 19090 \
  --ca-binary ./host/optee_example_openclaw_trusted_backend \
  --verify-mode none
```

Or with HMAC scope-token signing:

```bash
python3 ./host/backend_server.py \
  --bind 0.0.0.0 \
  --port 19090 \
  --ca-binary ./host/optee_example_openclaw_trusted_backend \
  --verify-mode hmac-sha256 \
  --hmac-key 'replace-me'
```

OpenClaw can then point `tools.trustedIsolation.backendBaseUrl` at:

```text
http://<raspberry-pi-ip>:19090
```

Matching OpenClaw config examples:

```json
{
  "tools": {
    "trustedIsolation": {
      "enabled": true,
      "backendBaseUrl": "http://<raspberry-pi-ip>:19090",
      "authorizePath": "/v1/trusted/authorize",
      "completePath": "/v1/trusted/complete",
      "verify": {
        "mode": "none"
      }
    }
  }
}
```

Or with HMAC:

```json
{
  "tools": {
    "trustedIsolation": {
      "enabled": true,
      "backendBaseUrl": "http://<raspberry-pi-ip>:19090",
      "authorizePath": "/v1/trusted/authorize",
      "completePath": "/v1/trusted/complete",
      "verify": {
        "mode": "hmac-sha256",
        "hmacKey": "replace-me"
      }
    }
  }
}
```

Example policy behavior in the TA:

- `echo`, `ls`, `pwd`, `printf` -> `dree`
- general `exec` -> `dia`
- `tar`, `scp`, `curl`, `wget` -> `duc`
- `rm -rf`, `/root/.ssh`, `shutdown`, `mkfs` -> `ddeny`

Notes:

- This example keeps the OpenClaw-side HTTP contract stable.
- The example HTTP shim supports `verify.mode = none` and `verify.mode = hmac-sha256`.
- `ed25519` is not implemented in this example shim.
- The TA currently uses a simple example policy and is meant as a starting
  point for a real TrustZone backend, not as a production policy engine.
