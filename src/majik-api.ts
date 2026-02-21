import { DEFAULT_RATE_LIMIT, MAX_RATE_LIMIT, TO_MINUTES } from "./constants";
import type {
  DomainWhitelist,
  IPWhitelist,
  MajikAPICreateOptions,
  MajikAPIJSON,
  MajikAPISettings,
  RateLimit,
  RateLimitFrequency,
} from "./types";
import {
  assertBoolean,
  assertPositiveInteger,
  assertRateLimitFrequency,
  assertString,
  assertStringArray,
  buildDefaultSettings,
  generateID,
  isValidISODate,
  sha256,
  validateDomain,
  validateIP,
} from "./utils";

// ─────────────────────────────────────────────
//  MajikAPI Class
// ─────────────────────────────────────────────

export class MajikAPI {
  // ── Private fields ───────────────────────────────────────────────────────
  //
  //  _id        — stable UUID. Primary key in Supabase. Never changes even
  //               when the key is rotated. Safe to FK against in audit tables.
  //
  //  _owner_id  — UUID of the user who owns this key. FK to auth.users.
  //
  //  _api_key   — SHA-256 hash of the raw plaintext key. Has a UNIQUE INDEX
  //               in Postgres (not the PK). Used as the Redis cache key.
  //               The raw key is never stored or logged anywhere.
  //
  //  _raw_api_key — Only populated immediately after create(). Cleared
  //                 (undefined) when reconstructed via fromJSON(). This is
  //                 the one and only moment the caller can read the plaintext.
  // ─────────────────────────────────────────────────────────────────────────

  private readonly _id: string;
  private readonly _owner_id: string;
  private _name: string;
  private _api_key: string;
  private _raw_api_key: string | undefined;
  private readonly _timestamp: Date;
  private _restricted: boolean;
  private _valid_until: Date | null;
  private _settings: MajikAPISettings;

  // ─────────────────────────────────────────────
  //  Private Constructor
  // ─────────────────────────────────────────────

  private constructor(
    id: string,
    owner_id: string,
    name: string,
    api_key: string,
    timestamp: Date,
    restricted: boolean,
    valid_until: Date | null,
    settings: MajikAPISettings,
    raw_api_key?: string,
  ) {
    this._id = id;
    this._owner_id = owner_id;
    this._name = name;
    this._api_key = api_key;
    this._timestamp = timestamp;
    this._restricted = restricted;
    this._valid_until = valid_until;
    this._settings = settings;
    this._raw_api_key = raw_api_key;
  }

  // ─────────────────────────────────────────────
  //  Static Factory: create()
  // ─────────────────────────────────────────────

  /**
   * Create a brand-new MajikAPI key instance.
   *
   * @param ownerID - UUID of the user who owns this key. Required.
   * @param text    - Optional raw key text. If omitted, a UUIDv4 is generated.
   * @param options - Optional name, expiry, restrictions, and settings.
   *
   * After creation, `instance.rawApiKey` holds the plaintext key. This is the
   * only moment it is accessible. Store it safely — it cannot be recovered.
   */
  static create(
    ownerID: string,
    text?: string,
    options: MajikAPICreateOptions = {},
  ): MajikAPI {
    assertString(ownerID, "ownerID");

    // Resolve raw key
    let rawKey: string;
    if (text !== undefined) {
      if (typeof text !== "string" || text.trim() === "") {
        throw new TypeError(
          "[MajikAPI] create(): 'text' must be a non-empty string if provided.",
        );
      }
      rawKey = text.trim();
    } else {
      rawKey = generateID();
    }

    const name = options.name ?? "Unnamed Key";
    if (typeof name !== "string" || name.trim() === "") {
      throw new TypeError(
        "[MajikAPI] create(): 'options.name' must be a non-empty string.",
      );
    }

    const restricted = options.restricted ?? false;
    assertBoolean(restricted, "options.restricted");

    let valid_until: Date | null = null;
    if (options.valid_until !== undefined && options.valid_until !== null) {
      valid_until = MajikAPI.parseDate(
        options.valid_until,
        "options.valid_until",
      );
      if (valid_until <= new Date()) {
        throw new RangeError(
          "[MajikAPI] create(): 'valid_until' must be a future date.",
        );
      }
    }

    const settings = buildDefaultSettings(options.settings);
    MajikAPI.validateSettings(settings);

    return new MajikAPI(
      generateID(), // _id        — stable primary key, separate from the key hash
      ownerID.trim(), // _owner_id
      name.trim(), // _name
      sha256(rawKey), // _api_key   — hash only, never store raw
      new Date(), // _timestamp
      restricted,
      valid_until,
      settings,
      rawKey, // _raw_api_key — only available on this fresh instance
    );
  }

  // ─────────────────────────────────────────────
  //  Static Factory: fromJSON()
  // ─────────────────────────────────────────────

  /**
   * Reconstruct a MajikAPI instance from a serialised MajikAPIJSON object.
   * Accepts the raw output of `toJSON()`, a Supabase row, or a Redis cache hit.
   *
   * `raw_api_key` is intentionally NOT restored — it is never in the JSON.
   */
  static fromJSON(data: MajikAPIJSON): MajikAPI {
    if (typeof data !== "object" || data === null || Array.isArray(data)) {
      throw new TypeError("[MajikAPI] fromJSON(): Expected a plain object.");
    }

    assertString(data.id, "id");
    assertString(data.owner_id, "owner_id");
    assertString(data.name, "name");
    assertString(data.api_key, "api_key");
    assertString(data.timestamp, "timestamp");

    if (!isValidISODate(data.timestamp)) {
      throw new TypeError(
        `[MajikAPI] fromJSON(): 'timestamp' is not a valid ISO date: "${data.timestamp}"`,
      );
    }

    if (typeof data.restricted !== "boolean") {
      throw new TypeError(
        "[MajikAPI] fromJSON(): 'restricted' must be a boolean.",
      );
    }

    if (data.valid_until !== null && data.valid_until !== undefined) {
      assertString(data.valid_until, "valid_until");
      if (!isValidISODate(data.valid_until as string)) {
        throw new TypeError(
          "[MajikAPI] fromJSON(): 'valid_until' is not a valid ISO date.",
        );
      }
    }

    if (typeof data.settings !== "object" || data.settings === null) {
      throw new TypeError(
        "[MajikAPI] fromJSON(): 'settings' must be an object.",
      );
    }

    const settings = buildDefaultSettings(
      data.settings as Partial<MajikAPISettings>,
    );
    MajikAPI.validateSettings(settings);

    return new MajikAPI(
      data.id,
      data.owner_id,
      data.name,
      data.api_key,
      new Date(data.timestamp),
      data.restricted as boolean,
      data.valid_until ? new Date(data.valid_until) : null,
      settings,
      undefined, // raw_api_key is never restored
    );
  }

  // ─────────────────────────────────────────────
  //  Serialisation
  // ─────────────────────────────────────────────

  /**
   * Serialise to a plain JSON-safe object matching MajikAPIJSON.
   * Safe to store in Supabase or cache in Redis.
   * raw_api_key is NEVER included.
   */
  toJSON(): MajikAPIJSON {
    return {
      id: this._id,
      owner_id: this._owner_id,
      name: this._name,
      api_key: this._api_key,
      timestamp: this._timestamp.toISOString(),
      restricted: this._restricted,
      valid_until: this._valid_until ? this._valid_until.toISOString() : null,
      settings: structuredClone(this._settings),
    };
  }

  // ─────────────────────────────────────────────
  //  Validation
  // ─────────────────────────────────────────────

  /**
   * Assert the integrity of all fields on this instance.
   * Throws a descriptive error for the first field that fails.
   */
  validate(): void {
    assertString(this._id, "id");
    assertString(this._owner_id, "owner_id");
    assertString(this._name, "name");
    assertString(this._api_key, "api_key");

    if (
      !(this._timestamp instanceof Date) ||
      isNaN(this._timestamp.getTime())
    ) {
      throw new TypeError(
        "[MajikAPI] validate(): 'timestamp' is not a valid Date.",
      );
    }

    assertBoolean(this._restricted, "restricted");

    if (this._valid_until !== null) {
      if (
        !(this._valid_until instanceof Date) ||
        isNaN(this._valid_until.getTime())
      ) {
        throw new TypeError(
          "[MajikAPI] validate(): 'valid_until' is not a valid Date.",
        );
      }
    }

    MajikAPI.validateSettings(this._settings);
  }

  // ─────────────────────────────────────────────
  //  Key Verification
  // ─────────────────────────────────────────────

  /**
   * Hash `text` and compare against the stored api_key hash.
   * This is the correct way to verify an incoming key at your API gateway.
   * Returns true if the key matches.
   */
  verify(text: string): boolean {
    if (typeof text !== "string" || text.trim() === "") {
      throw new TypeError(
        "[MajikAPI] verify(): Input must be a non-empty string.",
      );
    }
    return sha256(text.trim()) === this._api_key;
  }

  /** Alias for verify(). */
  matches(text: string): boolean {
    return this.verify(text);
  }

  // ─────────────────────────────────────────────
  //  Status Checks
  // ─────────────────────────────────────────────

  /** Returns true if valid_until is set and has passed. Always false if null. */
  isExpired(): boolean {
    if (this._valid_until === null) return false;
    return new Date() > this._valid_until;
  }

  /** Returns true only if the key is not expired and not restricted. */
  isActive(): boolean {
    return !this.isExpired() && !this._restricted;
  }

  // ─────────────────────────────────────────────
  //  Rate Limit
  // ─────────────────────────────────────────────

  /**
   * Set the rate limit for this key.
   *
   * The effective rate (normalised to req/min) cannot exceed MAX_RATE_LIMIT
   * (500 req/min). Attempting to set a higher rate will throw unless
   * bypassSafeLimit is explicitly passed as true.
   *
   * @param amount        - Number of allowed requests per frequency window.
   * @param frequency     - The time window unit.
   * @param bypassSafeLimit - When true, skips the MAX_RATE_LIMIT ceiling check.
   *                        Defaults to false. Use with caution.
   */
  setRateLimit(
    amount: number,
    frequency: RateLimitFrequency,
    bypassSafeLimit = false,
  ): void {
    assertPositiveInteger(amount, "amount");
    assertRateLimitFrequency(frequency, "frequency");
    assertBoolean(bypassSafeLimit, "bypassSafeLimit");

    if (!bypassSafeLimit) {
      const incomingRpm = amount * TO_MINUTES[frequency];
      const ceilingRpm =
        MAX_RATE_LIMIT.amount * TO_MINUTES[MAX_RATE_LIMIT.frequency];

      if (incomingRpm > ceilingRpm) {
        throw new RangeError(
          `[MajikAPI] setRateLimit(): The requested rate (${amount} per ${frequency} ` +
            `\u2248 ${incomingRpm.toFixed(4)} req/min) exceeds the system ceiling of ` +
            `${ceilingRpm.toFixed(4)} req/min (${MAX_RATE_LIMIT.amount} per ` +
            `${MAX_RATE_LIMIT.frequency}). ` +
            `Pass bypassSafeLimit = true to override this guard.`,
        );
      }
    }

    this._settings.rateLimit = { amount, frequency };
  }

  /** Reset the rate limit back to DEFAULT_RATE_LIMIT. */
  resetRateLimit(): void {
    this._settings.rateLimit = { ...DEFAULT_RATE_LIMIT };
  }

  // ─────────────────────────────────────────────
  //  Key Rotation
  // ─────────────────────────────────────────────

  /**
   * Rotate the API key. Generates a new raw key (or accepts a provided one),
   * hashes it, and replaces _api_key. The stable _id and _owner_id are
   * untouched, so all FK references in audit/event tables remain valid.
   *
   * After rotation, `rawApiKey` holds the new plaintext key. This is the only
   * moment it is accessible. The old key is immediately invalidated in-memory.
   *
   * IMPORTANT: After calling rotate(), you must:
   *   1. Save the new toJSON() to Supabase (updates the api_key column).
   *   2. Delete the old Redis cache entry (old hash key is now stale).
   *   3. Show the caller rawApiKey before discarding this instance.
   *
   * @param text - Optional new raw key. If omitted, a UUIDv4 is generated.
   */
  rotate(text?: string): void {
    let rawKey: string;
    if (text !== undefined) {
      if (typeof text !== "string" || text.trim() === "") {
        throw new TypeError(
          "[MajikAPI] rotate(): 'text' must be a non-empty string if provided.",
        );
      }
      rawKey = text.trim();
    } else {
      rawKey = generateID();
    }

    this._api_key = sha256(rawKey);
    this._raw_api_key = rawKey;
  }

  // ─────────────────────────────────────────────
  //  Mutation Methods
  // ─────────────────────────────────────────────

  /** Rename this key. */
  rename(name: string): void {
    assertString(name, "name");
    this._name = name.trim();
  }

  /**
   * Set or clear the expiry date.
   * Pass null to make the key never expire.
   */
  setExpiry(date: Date | string | null): void {
    if (date === null) {
      this._valid_until = null;
      return;
    }
    const parsed = MajikAPI.parseDate(date, "date");
    if (parsed <= new Date()) {
      throw new RangeError(
        "[MajikAPI] setExpiry(): Expiry date must be in the future.",
      );
    }
    this._valid_until = parsed;
  }

  /** Disable this key without deleting it. */
  restrict(): void {
    this._restricted = true;
  }

  /** Re-enable a previously restricted key. */
  unrestrict(): void {
    this._restricted = false;
  }

  /**
   * Permanently revoke this key. Sets valid_until to epoch (always expired)
   * and marks it restricted. Both flags must be cleared to undo this — prefer
   * deleting the Supabase row and creating a new key instead.
   */
  revoke(): void {
    this._valid_until = new Date(0);
    this._restricted = true;
  }

  // ─────────────────────────────────────────────
  //  IP Whitelist
  // ─────────────────────────────────────────────

  enableIPWhitelist(): void {
    this._settings.ipWhitelist.enabled = true;
  }

  disableIPWhitelist(): void {
    this._settings.ipWhitelist.enabled = false;
  }

  addIP(ip: string): void {
    assertString(ip, "ip");
    validateIP(ip.trim());
    const trimmed = ip.trim();
    if (!this._settings.ipWhitelist.addresses.includes(trimmed)) {
      this._settings.ipWhitelist.addresses.push(trimmed);
    }
  }

  removeIP(ip: string): void {
    assertString(ip, "ip");
    this._settings.ipWhitelist.addresses =
      this._settings.ipWhitelist.addresses.filter((a) => a !== ip.trim());
  }

  setIPWhitelist(addresses: string[]): void {
    assertStringArray(addresses, "addresses");
    addresses.forEach((ip) => validateIP(ip.trim()));
    this._settings.ipWhitelist.addresses = addresses.map((ip) => ip.trim());
  }

  clearIPWhitelist(): void {
    this._settings.ipWhitelist.addresses = [];
  }

  // ─────────────────────────────────────────────
  //  Domain Whitelist
  // ─────────────────────────────────────────────

  enableDomainWhitelist(): void {
    this._settings.domainWhitelist.enabled = true;
  }

  disableDomainWhitelist(): void {
    this._settings.domainWhitelist.enabled = false;
  }

  addDomain(domain: string): void {
    assertString(domain, "domain");
    validateDomain(domain.trim());
    const trimmed = domain.trim();
    if (!this._settings.domainWhitelist.domains.includes(trimmed)) {
      this._settings.domainWhitelist.domains.push(trimmed);
    }
  }

  removeDomain(domain: string): void {
    assertString(domain, "domain");
    this._settings.domainWhitelist.domains =
      this._settings.domainWhitelist.domains.filter((d) => d !== domain.trim());
  }

  setDomainWhitelist(domains: string[]): void {
    assertStringArray(domains, "domains");
    domains.forEach((d) => validateDomain(d.trim()));
    this._settings.domainWhitelist.domains = domains.map((d) => d.trim());
  }

  clearDomainWhitelist(): void {
    this._settings.domainWhitelist.domains = [];
  }

  // ─────────────────────────────────────────────
  //  Allowed Methods
  // ─────────────────────────────────────────────

  setAllowedMethods(methods: string[]): void {
    assertStringArray(methods, "methods");
    const valid = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
    for (const m of methods) {
      if (!valid.includes(m.toUpperCase())) {
        throw new Error(
          `[MajikAPI] setAllowedMethods(): Unknown HTTP method "${m}". Valid: ${valid.join(", ")}`,
        );
      }
    }
    this._settings.allowedMethods = methods.map((m) => m.toUpperCase());
  }

  clearAllowedMethods(): void {
    this._settings.allowedMethods = [];
  }

  // ─────────────────────────────────────────────
  //  Metadata
  // ─────────────────────────────────────────────

  setMetadata(key: string, value: unknown): void {
    assertString(key, "metadata key");
    this._settings.metadata = this._settings.metadata ?? {};
    this._settings.metadata[key] = value;
  }

  getMetadata(key: string): unknown {
    assertString(key, "metadata key");
    return this._settings.metadata?.[key];
  }

  deleteMetadata(key: string): void {
    assertString(key, "metadata key");
    if (this._settings.metadata) {
      delete this._settings.metadata[key];
    }
  }

  clearMetadata(): void {
    this._settings.metadata = {};
  }

  // ─────────────────────────────────────────────
  //  Getters
  // ─────────────────────────────────────────────

  /** The key's own stable UUID. Primary key in Supabase. */
  get id(): string {
    return this._id;
  }

  /** UUID of the user who owns this key. FK to auth.users. */
  get ownerId(): string {
    return this._owner_id;
  }

  get name(): string {
    return this._name;
  }

  /**
   * The SHA-256 hash of the raw key. This is what is stored in Supabase and
   * used as the Redis cache key prefix. Never the plaintext.
   */
  get apiKey(): string {
    return this._api_key;
  }

  /**
   * The raw plaintext key. Only defined immediately after create() or rotate().
   * Undefined after fromJSON() or any serialise/deserialise round-trip.
   * Treat this like a password — show it once and discard.
   */
  get rawApiKey(): string | undefined {
    return this._raw_api_key;
  }

  get createdAt(): Date {
    return new Date(this._timestamp);
  }

  get timestamp(): string {
    return this._timestamp.toISOString();
  }

  get restricted(): boolean {
    return this._restricted;
  }

  get validUntil(): Date | null {
    return this._valid_until ? new Date(this._valid_until) : null;
  }

  /** Returns a deep clone — mutations to the returned object have no effect. */
  get settings(): Readonly<MajikAPISettings> {
    return structuredClone(this._settings);
  }

  get rateLimit(): Readonly<RateLimit> {
    return { ...this._settings.rateLimit };
  }

  get ipWhitelist(): Readonly<IPWhitelist> {
    return structuredClone(this._settings.ipWhitelist);
  }

  get domainWhitelist(): Readonly<DomainWhitelist> {
    return structuredClone(this._settings.domainWhitelist);
  }

  get allowedMethods(): string[] {
    return [...(this._settings.allowedMethods ?? [])];
  }

  /**
   * Milliseconds until this key expires.
   * Returns -1 if the key never expires (valid_until is null).
   * Returns 0 if the key has already expired.
   */
  get msUntilExpiry(): number {
    if (this._valid_until === null) return -1;
    return Math.max(0, this._valid_until.getTime() - Date.now());
  }

  /**
   * Human-readable lifecycle status.
   *
   * "active"     — valid, not restricted, not expired.
   * "restricted" — manually disabled, not expired.
   * "expired"    — past valid_until date.
   * "revoked"    — permanently invalidated via revoke().
   */
  get status(): "active" | "restricted" | "expired" | "revoked" {
    if (this._valid_until?.getTime() === new Date(0).getTime())
      return "revoked";
    if (this.isExpired()) return "expired";
    if (this._restricted) return "restricted";
    return "active";
  }

  // ─────────────────────────────────────────────
  //  Private Static Utilities
  // ─────────────────────────────────────────────

  private static parseDate(value: Date | string, label: string): Date {
    if (value instanceof Date) {
      if (isNaN(value.getTime())) {
        throw new TypeError(`[MajikAPI] "${label}" is an invalid Date object.`);
      }
      return value;
    }
    if (typeof value === "string") {
      if (!isValidISODate(value)) {
        throw new TypeError(
          `[MajikAPI] "${label}" is not a valid ISO date string: "${value}"`,
        );
      }
      return new Date(value);
    }
    throw new TypeError(
      `[MajikAPI] "${label}" must be a Date instance or an ISO date string.`,
    );
  }

  private static validateSettings(settings: MajikAPISettings): void {
    if (typeof settings !== "object" || settings === null) {
      throw new TypeError("[MajikAPI] 'settings' must be an object.");
    }

    assertPositiveInteger(
      settings.rateLimit?.amount,
      "settings.rateLimit.amount",
    );
    assertRateLimitFrequency(
      settings.rateLimit?.frequency,
      "settings.rateLimit.frequency",
    );

    assertBoolean(
      settings.ipWhitelist?.enabled,
      "settings.ipWhitelist.enabled",
    );
    assertStringArray(
      settings.ipWhitelist?.addresses,
      "settings.ipWhitelist.addresses",
    );
    settings.ipWhitelist.addresses.forEach((ip) => validateIP(ip));

    assertBoolean(
      settings.domainWhitelist?.enabled,
      "settings.domainWhitelist.enabled",
    );
    assertStringArray(
      settings.domainWhitelist?.domains,
      "settings.domainWhitelist.domains",
    );
    settings.domainWhitelist.domains.forEach((d) => validateDomain(d));
  }

  // ─────────────────────────────────────────────
  //  Debug
  // ─────────────────────────────────────────────

  toString(): string {
    return `[MajikAPI id="${this._id}" owner="${this._owner_id}" name="${this._name}" status="${this.status}"]`;
  }

  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return this.toString();
  }
}

export default MajikAPI;
