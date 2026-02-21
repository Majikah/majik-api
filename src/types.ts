export type RateLimitFrequency = "seconds" | "minutes" | "hours";

export interface RateLimit {
  amount: number;
  frequency: RateLimitFrequency;
}

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
 */
export interface MajikAPIJSON {
  id: string;
  owner_id: string;
  name: string;
  api_key: string;
  timestamp: string;
  restricted: boolean;
  valid_until: string | null;
  settings: MajikAPISettings;
}

export interface MajikAPICreateOptions {
  name?: string;
  restricted?: boolean;
  valid_until?: Date | string | null;
  settings?: Partial<MajikAPISettings>;
}
