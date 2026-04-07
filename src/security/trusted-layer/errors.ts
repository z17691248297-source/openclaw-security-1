export type TrustedIsolationErrorCode =
  | "trusted_authorization_invalid_response"
  | "trusted_authorization_missing_scope_token"
  | "trusted_authorization_rejected"
  | "trusted_authorization_timeout"
  | "trusted_backend_unavailable"
  | "trusted_confirmation_invalid_response"
  | "trusted_confirmation_rejected"
  | "trusted_confirmation_timeout"
  | "trusted_complete_invalid_response"
  | "trusted_complete_timeout"
  | "trusted_evidence_write_failure"
  | "trusted_isolated_execution_unavailable"
  | "trusted_scope_token_expired"
  | "trusted_scope_token_verification_failed"
  | "trusted_scope_violation";

export class TrustedIsolationError extends Error {
  code: TrustedIsolationErrorCode;
  override cause?: unknown;

  constructor(
    code: TrustedIsolationErrorCode,
    message: string,
    options?: {
      cause?: unknown;
    },
  ) {
    super(message);
    this.name = "TrustedIsolationError";
    this.code = code;
    this.cause = options?.cause;
  }
}

export function isTrustedIsolationError(error: unknown): error is TrustedIsolationError {
  return error instanceof TrustedIsolationError;
}

export function toTrustedIsolationError(error: unknown): TrustedIsolationError | undefined {
  return isTrustedIsolationError(error) ? error : undefined;
}

export function createTrustedAuthorizationInvalidResponseError(
  cause?: unknown,
): TrustedIsolationError {
  return new TrustedIsolationError(
    "trusted_authorization_invalid_response",
    "trusted authorization invalid response",
    { cause },
  );
}

export function createTrustedAuthorizationMissingScopeTokenError(
  cause?: unknown,
): TrustedIsolationError {
  return new TrustedIsolationError(
    "trusted_authorization_missing_scope_token",
    "trusted authorization missing scope token",
    { cause },
  );
}

export function createTrustedAuthorizationRejectedError(
  reason?: string,
  cause?: unknown,
): TrustedIsolationError {
  return new TrustedIsolationError(
    "trusted_authorization_rejected",
    reason?.trim() || "trusted authorization rejected",
    { cause },
  );
}

export function createTrustedAuthorizationTimeoutError(cause?: unknown): TrustedIsolationError {
  return new TrustedIsolationError(
    "trusted_authorization_timeout",
    "trusted authorization timeout",
    {
      cause,
    },
  );
}

export function createTrustedBackendUnavailableError(cause?: unknown): TrustedIsolationError {
  return new TrustedIsolationError("trusted_backend_unavailable", "trusted backend unavailable", {
    cause,
  });
}

export function createTrustedConfirmationInvalidResponseError(
  cause?: unknown,
): TrustedIsolationError {
  return new TrustedIsolationError(
    "trusted_confirmation_invalid_response",
    "trusted confirmation invalid response",
    { cause },
  );
}

export function createTrustedConfirmationRejectedError(
  reason?: string,
  cause?: unknown,
): TrustedIsolationError {
  return new TrustedIsolationError(
    "trusted_confirmation_rejected",
    reason?.trim() || "trusted confirmation rejected",
    { cause },
  );
}

export function createTrustedConfirmationTimeoutError(cause?: unknown): TrustedIsolationError {
  return new TrustedIsolationError("trusted_confirmation_timeout", "trusted confirmation timeout", {
    cause,
  });
}

export function createTrustedCompleteInvalidResponseError(cause?: unknown): TrustedIsolationError {
  return new TrustedIsolationError(
    "trusted_complete_invalid_response",
    "trusted complete invalid response",
    {
      cause,
    },
  );
}

export function createTrustedCompleteTimeoutError(cause?: unknown): TrustedIsolationError {
  return new TrustedIsolationError("trusted_complete_timeout", "trusted complete timeout", {
    cause,
  });
}

export function createTrustedEvidenceWriteFailureError(cause?: unknown): TrustedIsolationError {
  return new TrustedIsolationError(
    "trusted_evidence_write_failure",
    "trusted evidence write failure",
    {
      cause,
    },
  );
}

export function createTrustedIsolatedExecutionUnavailableError(
  cause?: unknown,
): TrustedIsolationError {
  return new TrustedIsolationError(
    "trusted_isolated_execution_unavailable",
    "trusted isolated execution unavailable",
    { cause },
  );
}

export function createTrustedScopeTokenExpiredError(cause?: unknown): TrustedIsolationError {
  return new TrustedIsolationError("trusted_scope_token_expired", "trusted scope token expired", {
    cause,
  });
}

export function createTrustedScopeTokenVerificationFailedError(
  cause?: unknown,
): TrustedIsolationError {
  return new TrustedIsolationError(
    "trusted_scope_token_verification_failed",
    "trusted scope token verification failed",
    { cause },
  );
}

export function createTrustedScopeViolationError(detail: string): TrustedIsolationError {
  return new TrustedIsolationError("trusted_scope_violation", `trusted scope violation: ${detail}`);
}
