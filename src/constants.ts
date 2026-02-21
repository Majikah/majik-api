// ─────────────────────────────────────────────
//  Constants
// ─────────────────────────────────────────────

import { RateLimit, RateLimitFrequency } from "./types";

export const DEFAULT_RATE_LIMIT: RateLimit = {
  amount: 100,
  frequency: "minutes",
} as const;

/**
 * Hard ceiling for any rate limit set on a MajikAPI key.
 * No key — regardless of trust level — may exceed this without bypassSafeLimit.
 * Expressed in req/min for normalisation purposes; stored as a RateLimit for
 * consistency with the rest of the API.
 */
export const MAX_RATE_LIMIT: RateLimit = {
  amount: 500,
  frequency: "minutes",
} as const;

/** Multipliers to convert each frequency unit into requests-per-minute. */
export const TO_MINUTES: Record<RateLimitFrequency, number> = {
  seconds: 1 / 60,
  minutes: 1,
  hours: 60,
};
