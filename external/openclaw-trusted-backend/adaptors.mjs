import { createLocalTdxGuestService } from "./tdx-guest.mjs";

export function createTrustedBackendAdaptor(adaptorName) {
  const normalized = (adaptorName || "local-tdx").trim();

  if (normalized === "local-tdx") {
    const guestService = createLocalTdxGuestService();
    return {
      adaptor: "local-tdx",
      platform: "tdx",
      proofPath: "trusted-backend -> local cvm policy engine",
      getGuestInfo(params) {
        return guestService.getGuestInfo(params);
      },
      async attest(params) {
        return await guestService.attest(params);
      },
      async authorize({ request, evaluation }) {
        const attestation = await guestService.attest({
          phase: "authorize",
          request: evaluation.normalizedRequest ?? request,
        });
        return {
          proof: {
            platform: "tdx",
            adaptor: "local-tdx",
            proofPath: "local-cvm",
            matchedRuleId: evaluation.matchedRuleId,
            tdxGuest: attestation.summary,
          },
        };
      },
      async complete({ request }) {
        const attestation = await guestService.attest({
          phase: "complete",
          request,
        });
        return {
          proof: {
            platform: "tdx",
            adaptor: "local-tdx",
            phase: "complete",
            reqId: request.reqId,
            tdxGuest: attestation.summary,
          },
        };
      },
    };
  }

  if (normalized === "trustzone-remote-backend") {
    return {
      adaptor: "trustzone-remote-backend",
      platform: "trustzone",
      proofPath: "openclaw -> ree proxy -> secure-world tee call",
      async authorize({ evaluation }) {
        return {
          proof: {
            platform: "trustzone",
            adaptor: "trustzone-remote-backend",
            proofPath: "ree-proxy",
            teeCall: "smc/shared-memory authorize",
            matchedRuleId: evaluation.matchedRuleId,
          },
        };
      },
      async complete({ request }) {
        return {
          proof: {
            platform: "trustzone",
            adaptor: "trustzone-remote-backend",
            phase: "complete",
            reqId: request.reqId,
          },
        };
      },
    };
  }

  if (normalized === "keystone-remote-backend") {
    return {
      adaptor: "keystone-remote-backend",
      platform: "keystone",
      proofPath: "openclaw -> ree proxy -> enclave call",
      async authorize({ evaluation }) {
        return {
          proof: {
            platform: "keystone",
            adaptor: "keystone-remote-backend",
            proofPath: "ree-proxy",
            teeCall: "enclave authorize",
            matchedRuleId: evaluation.matchedRuleId,
          },
        };
      },
      async complete({ request }) {
        return {
          proof: {
            platform: "keystone",
            adaptor: "keystone-remote-backend",
            phase: "complete",
            reqId: request.reqId,
          },
        };
      },
    };
  }

  throw new Error(`Unsupported TRUSTED_BACKEND_ADAPTOR: ${normalized}`);
}
