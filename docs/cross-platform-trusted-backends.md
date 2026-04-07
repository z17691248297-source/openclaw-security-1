# Cross-Platform Trusted Backends

## Unified API

All trusted backends expose the same API:

- `POST /v1/trusted/authorize`
- `POST /v1/trusted/complete`
- `GET /healthz`

OpenClaw uses one execution gate and one client path regardless of TEE type.

## Shared Request / Response Shape

### Authorize Request

- `sid`
- `reqId`
- `action`
- `object`
- `scope`
- `context`
- `level`
- `seq`
- `ttlMs`
- `issuedAtMs`
- `normalizedScopeDigest`
- `requestDigest`

### Authorize Response

- `allow`
- `decision`
- `level`
- `reason`
- `matchedRuleId`
- `normalizedRequest`
- `classification`
- `scopeToken`
- `evidence`

### Complete Request

- `reqId`
- `sid`
- `toolName`
- `action`
- `object`
- `level`
- `decision`
- `matchedRuleId`
- `normalizedScopeDigest`
- `requestDigest`
- `startedAtMs`
- `finishedAtMs`
- `durationMs`
- `status`
- `resultDigest`
- `errorCode`
- `errorMessage`
- `context`

## Adaptor Responsibilities

### `local-tdx`

- primary implementation path
- runs the trusted backend next to the TDX-confined control plane
- returns TDX-oriented proof metadata
- preserves unified request/response semantics

### `trustzone-remote-backend`

- models `OpenClaw -> REE proxy -> secure world`
- OpenClaw does not call secure world directly
- the adaptor is responsible for:
  - local REE proxying
  - shared-memory / SMC handoff
  - proof metadata normalization back into the unified response

### `keystone-remote-backend`

- models `OpenClaw -> REE proxy -> enclave`
- OpenClaw does not call the enclave directly
- the adaptor is responsible for:
  - enclave RPC handoff
  - proof/result normalization
  - preserving the same authorize / complete semantics

## Communication Paths

### Intel TDX

```text
OpenClaw host REE
  -> HTTP to guest trusted backend
    -> local-tdx adaptor
      -> trusted rule engine / token minting / evidence semantics
```

### ARM TrustZone

```text
OpenClaw REE
  -> HTTP to trustzone remote backend
    -> REE proxy
      -> secure-world call
        -> normalized proof + decision back through the adaptor
```

### RISC-V Keystone

```text
OpenClaw REE
  -> HTTP to keystone remote backend
    -> REE proxy
      -> enclave call
        -> normalized proof + decision back through the adaptor
```

## Why OpenClaw Stays Uniform

OpenClaw does not branch on:

- attestation transport
- secure-world invocation details
- enclave RPC details
- TDX guest internals

It only depends on:

- canonical request generation
- unified authorize response
- scope token verification
- unified complete semantics
- evidence validation

This keeps the OpenClaw patch surface small while allowing per-platform backend evolution behind adaptor boundaries.

## Current Status

- TDX path is the complete prototype path
- TrustZone and Keystone paths are minimal adaptor/proof stubs today
- all three already share the same public API and response schema
- the next platform-specific step is to replace adaptor proof placeholders with real attestation-backed transports without changing OpenClaw's client contract
