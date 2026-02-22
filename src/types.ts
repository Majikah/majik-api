export type RateLimitFrequency = "seconds" | "minutes" | "hours";

export type QuotaFrequency =
  | "hours"
  | "days"
  | "weeks"
  | "months"
  | "quarters"
  | "years";

export interface RateLimit {
  amount: number;
  frequency: RateLimitFrequency;
}

/**
 * Quota controls how many total requests (or requests within a rolling window)
 * are permitted for this key.
 *
 * - `fixed`    — A lifetime cap. Once `limit` total requests have been made,
 *                the key is considered at quota. No time window applies.
 *
 * - `periodic` — A rolling/periodic cap. Resets every `frequency` window
 *                (e.g. 1 000 requests per day, 50 000 per month).
 *
 * - `null`     — No quota. Unlimited usage (subject only to rate limiting).
 */
export type Quota =
  | { type: "fixed"; limit: number }
  | { type: "periodic"; limit: number; frequency: QuotaFrequency }
  | null;

export interface IPWhitelist {
  enabled: boolean;
  addresses: string[];
}

export interface DomainWhitelist {
  enabled: boolean;
  domains: string[];
}

export interface MajikAPISettings {
  rateLimit: RateLimit;
  quota: Quota;
  ipWhitelist: IPWhitelist;
  domainWhitelist: DomainWhitelist;
  allowedMethods?: string[];
  metadata?: Record<string, unknown>;
}

/**
 * The serialised shape stored in Supabase and cached in Redis.
 *
 * id       — stable UUID primary key in Supabase. Never changes, even on
 *            key rotation. Safe to use as a FK in audit/event tables.
 * owner_id — FK to auth.users. Identifies who owns this key.
 * api_key  — SHA-256 hash of the raw plaintext key. Has a UNIQUE INDEX in
 *            Postgres (not the PK). Used as the Redis cache key prefix.
 *            The raw key is never stored anywhere.
 * is_valid — Computed convenience flag. True when the key is active (not
 *            expired, not restricted). Does NOT account for quota — use
 *            isQuotaExceeded() for runtime quota checks.
 */
export interface MajikAPIJSON {
  id: string;
  owner_id: string;
  name: string;
  api_key: string;
  timestamp: string;
  restricted: boolean;
  valid_until: string | null;
  is_valid: boolean;
  settings: MajikAPISettings;
}

export interface MajikAPICreateOptions {
  name?: string;
  restricted?: boolean;
  valid_until?: Date | string | null;
  settings?: Partial<MajikAPISettings>;
}
