/**
 * errors.ts
 * MajikAPI error hierarchy.
 */

export class MajikAPIError extends Error {
  cause?: unknown;
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = "MajikAPIError";
    this.cause = cause;
  }
}

export class MajikAPIValidationError extends MajikAPIError {
  field?: string;
  constructor(message: string, field?: string, cause?: unknown) {
    super(message, cause);
    this.name = "MajikAPIValidationError";
    this.field = field;
  }
}

export class MajikAPIRateLimitError extends MajikAPIError {
  constructor(message: string, cause?: unknown) {
    super(message, cause);
    this.name = "MajikAPIRateLimitError";
  }
}
