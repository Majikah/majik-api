/**
 * validator.ts
 * Input validation and assertion helpers for MajikAPI.
 */

import { MajikAPIValidationError, MajikAPIRateLimitError } from "./errors";
import { parseDateString } from "./utils";
import { MAX_RATE_LIMIT, TO_MINUTES } from "./constants";
import type {
  MajikAPISettings,
  QuotaFrequency,
  RateLimitFrequency,
  MajikAPIJSON,
} from "./types";

const VALID_QUOTA_FREQUENCIES: QuotaFrequency[] = [
  "hours",
  "days",
  "weeks",
  "months",
  "quarters",
  "years",
];

export class MajikAPIValidator {
  static assertString(value: unknown, field: string): asserts value is string {
    if (typeof value !== "string" || value.trim() === "") {
      throw new MajikAPIValidationError(
        `${field} must be a non-empty string.`,
        field,
      );
    }
  }

  static assertBoolean(
    value: unknown,
    field: string,
  ): asserts value is boolean {
    if (typeof value !== "boolean") {
      throw new MajikAPIValidationError(`${field} must be a boolean.`, field);
    }
  }

  static assertPositiveInteger(
    value: unknown,
    field: string,
  ): asserts value is number {
    if (typeof value !== "number" || !Number.isInteger(value) || value <= 0) {
      throw new MajikAPIValidationError(
        `${field} must be a positive integer.`,
        field,
      );
    }
  }

  static assertRateLimitFrequency(
    value: unknown,
    field: string,
  ): asserts value is RateLimitFrequency {
    const valid: RateLimitFrequency[] = ["seconds", "minutes", "hours"];
    if (!valid.includes(value as RateLimitFrequency)) {
      throw new TypeError(
        `"${field}" must be one of: ${valid.join(", ")}. Received: ${JSON.stringify(value)}`,
      );
    }
  }

  static validateQuotaFrequency(
    value: unknown,
    label: string,
  ): asserts value is QuotaFrequency {
    if (!VALID_QUOTA_FREQUENCIES.includes(value as QuotaFrequency)) {
      throw new MajikAPIValidationError(
        `"${label}" must be one of: ${VALID_QUOTA_FREQUENCIES.join(", ")}. Got: "${value}"`,
        label,
      );
    }
  }

  static validateRateLimitCeiling(
    amount: number,
    frequency: RateLimitFrequency,
    bypassSafeLimit: boolean,
  ): void {
    if (bypassSafeLimit) return;

    const incomingRpm = amount * (TO_MINUTES[frequency] || 1);
    const ceilingRpm =
      MAX_RATE_LIMIT.amount * (TO_MINUTES[MAX_RATE_LIMIT.frequency] || 1);

    if (incomingRpm > ceilingRpm) {
      throw new MajikAPIRateLimitError(
        `The requested rate (${amount} per ${frequency} ≈ ${incomingRpm.toFixed(4)} req/min) ` +
          `exceeds the system ceiling of ${ceilingRpm.toFixed(4)} req/min.`,
      );
    }
  }

  static validateSettings(settings: MajikAPISettings): void {
    if (typeof settings !== "object" || settings === null) {
      throw new MajikAPIValidationError("'settings' must be an object.");
    }

    if (settings.rateLimit) {
      this.assertPositiveInteger(
        settings.rateLimit.amount,
        "settings.rateLimit.amount",
      );
      // Assert frequency as needed
    }

    if (settings.quota !== null && settings.quota !== undefined) {
      this.assertPositiveInteger(settings.quota.limit, "settings.quota.limit");
      if (settings.quota.type === "periodic") {
        this.validateQuotaFrequency(
          settings.quota.frequency,
          "settings.quota.frequency",
        );
      } else if (settings.quota.type !== "fixed") {
        throw new MajikAPIValidationError(
          `Invalid quota type: ${(settings.quota as any).type}`,
          "settings.quota.type",
        );
      }
    }
  }

  static validateJSON(data: unknown): asserts data is MajikAPIJSON {
    if (typeof data !== "object" || data === null || Array.isArray(data)) {
      throw new MajikAPIValidationError(
        "Expected a plain object for MajikAPIJSON.",
      );
    }

    const d = data as Record<string, unknown>;
    this.assertString(d.id, "id");
    this.assertString(d.owner_id, "owner_id");
    this.assertString(d.name, "name");
    this.assertString(d.api_key, "api_key");
    this.assertString(d.timestamp, "timestamp");
    this.assertBoolean(d.restricted, "restricted");
  }

  static validateFutureDate(dateInput: Date | string, label: string): Date {
    const parsed = parseDateString(dateInput, label);
    if (parsed <= new Date()) {
      throw new MajikAPIValidationError(
        `'${label}' must be a future date.`,
        label,
      );
    }
    return parsed;
  }
}

// Freeze static methods
Object.freeze(MajikAPIValidator);

// Freeze instance methods
Object.freeze(MajikAPIValidator.prototype);
