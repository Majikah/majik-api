import { DEFAULT_RATE_LIMIT } from "./constants";
import { MajikAPIValidationError } from "./errors";
import { MajikAPIValidator } from "./validator";

import type {
  DomainWhitelist,
  IPWhitelist,
  MajikAPICreateOptions,
  MajikAPIJSON,
  MajikAPISettings,
  Quota,
  QuotaFrequency,
  RateLimit,
  RateLimitFrequency,
} from "./types";

import {
  assertStringArray,
  buildDefaultSettings,
  generateID,
  isValidISODate,
  sha256,
  validateDomain,
  validateIP,
} from "./utils";

// ─────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────

const HTTP_METHODS = [
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "HEAD",
  "OPTIONS",
] as const;

const VALID_HTTP_METHODS = new Set<string>(HTTP_METHODS);

const REVOKED_TIMESTAMP = 0;

/**
 * MajikAPI
 *
 * A domain model for managing API-key resources within the Majikah
 * ecosystem.
 *
 * MajikAPI encapsulates:
 *
 * - API-key generation and SHA-256 hashing
 * - Stable API-key resource identity
 * - One-time plaintext credential access
 * - Credential verification and rotation
 * - Key lifecycle and expiration management
 * - Rate-limit configuration
 * - Fixed and periodic quota configuration
 * - IP and domain whitelisting
 * - HTTP method restrictions
 * - Arbitrary application metadata
 * - Opaque application-level reference IDs
 * - JSON serialization and hydration
 * - Runtime integrity validation
 *
 * ## Security Model
 *
 * The persistent API credential is represented internally by its SHA-256
 * digest (`apiKey`). The plaintext credential (`rawApiKey`) is only exposed
 * immediately after creation or rotation and is intentionally excluded from
 * serialized output.
 *
 * Consumers should therefore treat `rawApiKey` like a password:
 *
 * ```ts
 * const api = MajikAPI.create("user_123");
 *
 * console.log(api.rawApiKey);
 * // Show or securely deliver the credential to the consumer.
 *
 * await save(api.toJSON());
 * // rawApiKey is never persisted by toJSON().
 * ```
 *
 * ## Identity Model
 *
 * Every API-key resource has two conceptually separate identifiers:
 *
 * 1. `id`
 *    Stable resource identifier. This remains unchanged across key rotation.
 *
 * 2. `apiKey`
 *    SHA-256 digest of the current authentication credential.
 *
 * This separation allows database rows, audit records, foreign keys, and
 * other references to remain stable when the underlying credential changes.
 *
 * ## Persistence
 *
 * MajikAPI is persistence-agnostic. It does not require a particular
 * database, cache, framework, API gateway, or hosting provider.
 *
 * Use:
 *
 * - `toJSON()` to produce a persistence-safe representation.
 * - `fromJSON()` to reconstruct an instance.
 *
 * ## Runtime Usage
 *
 * MajikAPI intentionally does not maintain distributed request counters.
 * Rate-limit and quota enforcement requiring external usage state should be
 * performed by the surrounding application infrastructure.
 *
 * @example
 * ```ts
 * import { MajikAPI } from "@majikah/majik-api";
 *
 * const api = MajikAPI.create(
 *   "user_123",
 *   undefined,
 *   {
 *     name: "Production API Key",
 *   },
 * );
 *
 * // Plaintext credential is available immediately after creation.
 * const rawKey = api.rawApiKey;
 *
 * // Persist only the safe representation.
 * const record = api.toJSON();
 *
 * // Later, reconstruct the resource.
 * const restored = MajikAPI.fromJSON(record);
 *
 * // Verify a client-supplied credential.
 * const valid = restored.verify("client-key");
 * ```
 *
 * @see {@link MajikAPIValidator}
 * @see {@link MajikAPIValidationError}
 * @see {@link MajikAPIRateLimitError}
 */
export class MajikAPI {
  // ─────────────────────────────────────────────
  // Private state
  // ─────────────────────────────────────────────

  /**
   * Stable API-key resource identifier.
   *
   * This identifier represents the API-key resource itself rather than the
   * current authentication credential.
   *
   * Unlike `apiKey`, this value does not change when the credential is rotated.
   *
   * Typical uses include:
   *
   * - database primary keys
   * - foreign-key references
   * - audit records
   * - ownership relationships
   * - application-level resource URLs
   *
   * @private
   * @readonly
   */
  private readonly _id: string;

  /**
   * Identifier of the user or entity that owns the API key.
   *
   * MajikAPI treats the value as an opaque identifier and does not impose
   * database-specific semantics on it.
   *
   * @private
   * @readonly
   */
  private readonly _owner_id: string;

  /**
   * Human-readable name assigned to the API key.
   *
   * This is descriptive metadata only and does not participate in
   * credential verification.
   *
   * @private
   */
  private _name: string;

  /**
   * SHA-256 digest of the current plaintext API credential.
   *
   * The plaintext credential is intentionally never stored in this
   * persistent field.
   *
   * This value is suitable for persistence and credential comparison.
   *
   * @private
   */
  private _api_key: string;

  /**
   * Temporary plaintext API credential.
   *
   * This value is populated only when:
   *
   * - a key is created through `create()`, or
   * - a key is rotated through `rotate()`.
   *
   * It is intentionally not serialized by `toJSON()`.
   *
   * When an instance is reconstructed using `fromJSON()`, this field is
   * intentionally undefined.
   *
   * Consumers should treat this value as sensitive credential material and
   * discard it after securely delivering it to the intended recipient.
   *
   * @private
   */
  private _raw_api_key?: string;

  /**
   * Timestamp at which the API-key resource was created.
   *
   * This value is immutable for the lifetime of the resource and does not
   * change during credential rotation.
   *
   * @private
   * @readonly
   */
  private readonly _timestamp: Date;

  /**
   * Administrative restriction flag.
   *
   * When `true`, the key is manually disabled.
   *
   * A restricted key cannot be active even when it has not expired.
   *
   * @private
   */
  private _restricted: boolean;

  /**
   * Absolute expiration timestamp.
   *
   * `null` means that the API key does not have an expiration date.
   *
   * @private
   */
  private _valid_until: Date | null;

  /**
   * Complete API-key configuration.
   *
   * This includes:
   *
   * - rate limits
   * - quotas
   * - IP whitelist
   * - domain whitelist
   * - allowed HTTP methods
   * - application metadata
   *
   * @private
   */
  private _settings: MajikAPISettings;

  /**
   * Optional opaque reference supplied by the consuming application.
   *
   * MajikAPI does not interpret this value. It may be used to associate
   * the API key with another entity such as an organization, project,
   * tenant, application, integration, or internal record.
   *
   * @private
   */
  private _reference_id: string | null;

  // ─────────────────────────────────────────────
  // Constructor
  // ─────────────────────────────────────────────

  /**
   * Construct an internal MajikAPI entity.
   *
   * The constructor is intentionally private. Consumers should use
   * {@link MajikAPI.create} when creating a new resource or
   * {@link MajikAPI.fromJSON} when reconstructing persisted state.
   *
   * @param params Internal entity state.
   * @param params.id Stable API-key resource identifier.
   * @param params.ownerId Identifier of the resource owner.
   * @param params.name Human-readable API-key name.
   * @param params.apiKey SHA-256 digest of the plaintext API key.
   * @param params.timestamp Resource creation timestamp.
   * @param params.restricted Administrative restriction state.
   * @param params.validUntil Optional expiration timestamp.
   * @param params.settings API-key runtime configuration.
   * @param params.rawApiKey Optional plaintext credential available only for
   * freshly created or rotated keys.
   * @param params.referenceId Optional application-defined reference.
   *
   * @private
   */
  private constructor(params: {
    id: string;
    ownerId: string;
    name: string;
    apiKey: string;
    timestamp: Date;
    restricted: boolean;
    validUntil: Date | null;
    settings: MajikAPISettings;
    rawApiKey?: string;
    referenceId?: string | null;
  }) {
    this._id = params.id;
    this._owner_id = params.ownerId;
    this._name = params.name;
    this._api_key = params.apiKey;
    this._timestamp = new Date(params.timestamp);
    this._restricted = params.restricted;
    this._valid_until = params.validUntil ? new Date(params.validUntil) : null;
    this._settings = params.settings;
    this._raw_api_key = params.rawApiKey;
    this._reference_id = params.referenceId ?? null;
  }

  // ─────────────────────────────────────────────
  // Factory methods
  // ─────────────────────────────────────────────

  /**
   * Create a new MajikAPI resource.
   *
   * If `text` is omitted, the library generates a new identifier to use as
   * the plaintext API credential.
   *
   * The plaintext credential is temporarily available through
   * {@link rawApiKey}.
   *
   * The credential is immediately hashed before being stored in the
   * persistent `_api_key` field.
   *
   * @param ownerID Identifier of the owner of the API key.
   * @param text Optional plaintext API credential. If omitted, one is
   * automatically generated.
   * @param options Optional API-key configuration.
   *
   * @returns A newly initialized MajikAPI instance.
   *
   * @throws {MajikAPIValidationError} When any supplied argument or option
   * fails validation.
   *
   * @example
   * ```ts
   * const api = MajikAPI.create(
   *   "user_123",
   *   undefined,
   *   {
   *     name: "Production",
   *   },
   * );
   *
   * console.log(api.rawApiKey);
   * ```
   */
  static create(
    ownerID: string,
    text?: string,
    options: MajikAPICreateOptions = {},
  ): MajikAPI {
    MajikAPIValidator.assertString(ownerID, "ownerID");

    const rawKey = MajikAPI.resolveRawKey(text, "create");

    const name = MajikAPI.normalizeName(options.name);

    const restricted = options.restricted ?? false;

    MajikAPIValidator.assertBoolean(restricted, "options.restricted");

    const validUntil =
      options.valid_until === undefined || options.valid_until === null
        ? null
        : MajikAPIValidator.validateFutureDate(
            options.valid_until,
            "options.valid_until",
          );

    const settings = MajikAPI.createSettings(options.settings);

    const referenceId = MajikAPI.normalizeOptionalString(
      options.referenceId,
      "options.referenceId",
    );

    return new MajikAPI({
      id: generateID(),
      ownerId: ownerID.trim(),
      name,
      apiKey: sha256(rawKey),
      timestamp: new Date(),
      restricted,
      validUntil,
      settings,
      rawApiKey: rawKey,
      referenceId,
    });
  }

  /**
   * Reconstruct a MajikAPI resource from serialized state.
   *
   * This method is intended for loading API-key resources from a database,
   * cache, API response, or any other serialized representation produced by
   * {@link toJSON}.
   *
   * The plaintext API credential is deliberately not restored.
   *
   * This means:
   *
   * ```ts
   * const restored = MajikAPI.fromJSON(data);
   *
   * restored.rawApiKey;
   * // undefined
   * ```
   *
   * Credential verification continues to work because the stored SHA-256
   * digest is sufficient for comparison.
   *
   * @param data Serialized API-key state.
   *
   * @returns A reconstructed MajikAPI instance.
   *
   * @throws {MajikAPIValidationError} When the serialized representation
   * is malformed or contains invalid state.
   *
   * @example
   * ```ts
   * const data = api.toJSON();
   * const restored = MajikAPI.fromJSON(data);
   *
   * restored.verify(clientProvidedKey);
   * ```
   */
  static fromJSON(data: MajikAPIJSON): MajikAPI {
    MajikAPIValidator.validateJSON(data);

    const validUntil =
      data.valid_until === null || data.valid_until === undefined
        ? null
        : MajikAPI.parseSerializedDate(data.valid_until, "valid_until");

    const timestamp = MajikAPI.parseSerializedDate(data.timestamp, "timestamp");

    if (
      typeof data.settings !== "object" ||
      data.settings === null ||
      Array.isArray(data.settings)
    ) {
      throw new MajikAPIValidationError(
        "'settings' must be a plain object.",
        "settings",
      );
    }

    const settings = MajikAPI.createSettings(
      data.settings as Partial<MajikAPISettings>,
    );

    const referenceId =
      data.reference_id === null || data.reference_id === undefined
        ? null
        : MajikAPI.normalizeOptionalString(data.reference_id, "reference_id");

    return new MajikAPI({
      id: data.id,
      ownerId: data.owner_id,
      name: data.name,
      apiKey: data.api_key,
      timestamp,
      restricted: data.restricted,
      validUntil,
      settings,
      rawApiKey: undefined,
      referenceId,
    });
  }

  // ─────────────────────────────────────────────
  // Serialization
  // ─────────────────────────────────────────────

  /**
   * Serialize this API-key resource into a JSON-safe representation.
   *
   * The serialized representation is designed for persistence in databases,
   * caches, or API responses.
   *
   * The plaintext `rawApiKey` is NEVER included.
   *
   * The serialized `api_key` field contains the SHA-256 digest.
   *
   * Mutable settings are deep-cloned so modifications to the returned object
   * cannot mutate the live MajikAPI instance.
   *
   * @returns A persistence-safe MajikAPIJSON object.
   *
   * @example
   * ```ts
   * const api = MajikAPI.create("user_123");
   *
   * const record = api.toJSON();
   *
   * await database.apiKeys.insert(record);
   * ```
   */
  toJSON(): MajikAPIJSON {
    return {
      id: this._id,
      owner_id: this._owner_id,
      name: this._name,
      api_key: this._api_key,
      timestamp: this._timestamp.toISOString(),
      restricted: this._restricted,
      valid_until: this._valid_until?.toISOString() ?? null,
      is_valid: this.is_valid,
      settings: structuredClone(this._settings),
      reference_id: this._reference_id,
    };
  }

  // ─────────────────────────────────────────────
  // Validation
  // ─────────────────────────────────────────────

  /**
   * Validate the integrity of the current in-memory resource.
   *
   * This validates the object's internal state rather than checking whether
   * the API key is currently active.
   *
   * A successful call returns normally.
   *
   * @returns `void`.
   *
   * @throws {MajikAPIValidationError} When any internal field violates the
   * MajikAPI domain constraints.
   *
   * @example
   * ```ts
   * api.validate();
   * ```
   */
  validate(): void {
    MajikAPIValidator.assertString(this._id, "id");

    MajikAPIValidator.assertString(this._owner_id, "owner_id");

    MajikAPIValidator.assertString(this._name, "name");

    MajikAPIValidator.assertString(this._api_key, "api_key");

    MajikAPI.assertValidDate(this._timestamp, "timestamp");

    MajikAPIValidator.assertBoolean(this._restricted, "restricted");

    if (this._valid_until !== null) {
      MajikAPI.assertValidDate(this._valid_until, "valid_until");
    }

    if (this._reference_id !== null) {
      MajikAPIValidator.assertString(this._reference_id, "reference_id");
    }

    MajikAPI.validateSettings(this._settings);
  }

  // ─────────────────────────────────────────────
  // API key verification
  // ─────────────────────────────────────────────

  /**
   * Verify a plaintext API credential against the stored SHA-256 digest.
   *
   * Leading and trailing whitespace is removed before comparison.
   *
   * This method only verifies credential equality. It does not check:
   *
   * - whether the key is restricted
   * - whether the key is expired
   * - whether quota has been exceeded
   * - whether a request originates from an allowed IP
   * - whether a request uses an allowed domain or HTTP method
   *
   * Those checks are represented separately by the MajikAPI state and
   * configuration APIs.
   *
   * @param text Plaintext credential supplied by the caller.
   *
   * @returns `true` when the supplied credential matches the stored hash;
   * otherwise `false`.
   *
   * @throws {MajikAPIValidationError} When `text` is empty or not a string.
   *
   * @example
   * ```ts
   * if (api.verify(clientApiKey)) {
   *   // Credential matches.
   * }
   * ```
   */
  verify(text: string): boolean {
    MajikAPIValidator.assertString(text, "text");

    return sha256(text.trim()) === this._api_key;
  }

  /**
   * Alias for {@link verify}.
   *
   * @param text Plaintext API credential.
   *
   * @returns `true` when the credential matches.
   *
   * @throws {MajikAPIValidationError} When the input is invalid.
   *
   * @example
   * ```ts
   * api.matches(clientApiKey);
   * ```
   */
  matches(text: string): boolean {
    return this.verify(text);
  }

  // ─────────────────────────────────────────────
  // Lifecycle / status
  // ─────────────────────────────────────────────

  /**
   * Determine whether the API key has expired.
   *
   * A key without an expiration date (`validUntil === null`) is never
   * considered expired.
   *
   * @returns `true` when `validUntil` exists and is in the past;
   * otherwise `false`.
   *
   * @example
   * ```ts
   * if (api.isExpired()) {
   *   // Do not accept the credential.
   * }
   * ```
   */
  isExpired(): boolean {
    return (
      this._valid_until !== null && Date.now() > this._valid_until.getTime()
    );
  }

  /**
   * Determine whether the API key is currently active.
   *
   * A key is active only when:
   *
   * - it is not expired, and
   * - it is not manually restricted.
   *
   * Quota state is intentionally excluded because quota evaluation requires
   * externally tracked usage information.
   *
   * @returns `true` when the key is operationally active.
   *
   * @example
   * ```ts
   * if (!api.isActive()) {
   *   // Reject or disable the API request.
   * }
   * ```
   */
  isActive(): boolean {
    return !this.isExpired() && !this._restricted;
  }

  /**
   * Permanently revoke the API key.
   *
   * Revocation marks the key as restricted and sets its expiration timestamp
   * to the Unix epoch (`1970-01-01T00:00:00.000Z`).
   *
   * A revoked key is therefore always inactive.
   *
   * @example
   * ```ts
   * api.revoke();
   *
   * console.log(api.status);
   * // "revoked"
   * ```
   */
  revoke(): void {
    this._restricted = true;
    this._valid_until = new Date(REVOKED_TIMESTAMP);
  }

  /**
   * Temporarily restrict the API key.
   *
   * Restriction disables the key without deleting its persisted resource
   * identity or other configuration.
   *
   * @example
   * ```ts
   * api.restrict();
   *
   * console.log(api.isActive());
   * // false
   * ```
   */
  restrict(): void {
    this._restricted = true;
  }

  /**
   * Remove an administrative restriction from the API key.
   *
   * Removing the restriction does not remove expiration or revocation state.
   *
   * For example, a revoked key remains revoked because its expiration is set
   * to the Unix epoch.
   *
   * @example
   * ```ts
   * api.restrict();
   * api.unrestrict();
   * ```
   */
  unrestrict(): void {
    this._restricted = false;
  }

  // ─────────────────────────────────────────────
  // Key rotation
  // ─────────────────────────────────────────────

  /**
   * Rotate the API credential.
   *
   * Rotation replaces the current credential hash while preserving the
   * stable API-key resource identity.
   *
   * The old credential immediately stops matching.
   *
   * When `text` is omitted, a new credential is automatically generated.
   *
   * After rotation, the new plaintext credential is available through
   * {@link rawApiKey}.
   *
   * Rotation does NOT change:
   *
   * - `id`
   * - `ownerId`
   * - `timestamp`
   * - `name`
   * - lifecycle state
   * - expiration
   * - settings
   * - reference ID
   *
   * @param text Optional replacement plaintext credential.
   *
   * @throws {MajikAPIValidationError} When an explicit credential is empty
   * or otherwise invalid.
   *
   * @example
   * ```ts
   * const previousKey = api.rawApiKey;
   *
   * api.rotate();
   *
   * const newKey = api.rawApiKey;
   *
   * api.verify(previousKey!);
   * // false
   *
   * api.verify(newKey!);
   * // true
   * ```
   */
  rotate(text?: string): void {
    const rawKey = MajikAPI.resolveRawKey(text, "rotate");

    this._api_key = sha256(rawKey);

    this._raw_api_key = rawKey;
  }

  // ─────────────────────────────────────────────
  // Core metadata mutation
  // ─────────────────────────────────────────────

  /**
   * Rename the API key.
   *
   * The name is trimmed before being stored and must be a non-empty string.
   *
   * @param name New human-readable name.
   *
   * @throws {MajikAPIValidationError} When `name` is invalid.
   *
   * @example
   * ```ts
   * api.rename("Production API");
   * ```
   */
  rename(name: string): void {
    this._name = MajikAPI.normalizeName(name);
  }

  /**
   * Set or clear the application's opaque reference ID.
   *
   * MajikAPI does not interpret or validate the semantic meaning of this
   * identifier.
   *
   * Passing `null` removes the reference.
   *
   * @param referenceId Application-defined reference, or `null` to clear.
   *
   * @throws {MajikAPIValidationError} When a non-null value is not a
   * non-empty string.
   *
   * @example
   * ```ts
   * api.setReferenceId(
   *   "organization_123",
   * );
   *
   * api.setReferenceId(null);
   * ```
   */
  setReferenceId(referenceId: string | null): void {
    this._reference_id = MajikAPI.normalizeOptionalString(
      referenceId,
      "referenceId",
    );
  }

  /**
   * Set or clear the API-key expiration date.
   *
   * The supplied date must be in the future.
   *
   * Pass `null` to remove expiration entirely.
   *
   * @param date Future `Date`, future ISO 8601 string, or `null`.
   *
   * @throws {MajikAPIValidationError} When the supplied value is invalid.
   *
   * @example
   * ```ts
   * api.setExpiry(
   *   "2099-01-01T00:00:00.000Z",
   * );
   * ```
   *
   * @example
   * ```ts
   * api.setExpiry(null);
   * // Key no longer expires.
   * ```
   */
  setExpiry(date: Date | string | null): void {
    if (date === null) {
      this._valid_until = null;

      return;
    }

    this._valid_until = MajikAPIValidator.validateFutureDate(date, "date");
  }

  // ─────────────────────────────────────────────
  // Rate limiting
  // ─────────────────────────────────────────────

  /**
   * Configure the request rate limit.
   *
   * The requested amount is validated against the library's configured
   * safe rate ceiling unless `bypassSafeLimit` is explicitly enabled.
   *
   * @param amount Number of requests permitted per frequency window.
   * Must be a positive integer.
   * @param frequency Rate-limit frequency unit.
   * @param bypassSafeLimit Explicitly bypass the configured safe ceiling.
   *
   * @throws {MajikAPIValidationError} When the amount, frequency, or bypass
   * flag is invalid.
   *
   * @throws {MajikAPIRateLimitError} When the requested rate exceeds the
   * configured safe ceiling and bypass is disabled.
   *
   * @example
   * ```ts
   * api.setRateLimit(
   *   100,
   *   "minutes",
   * );
   * ```
   *
   * @example
   * ```ts
   * // Explicit administrative override.
   * api.setRateLimit(
   *   5000,
   *   "minutes",
   *   true,
   * );
   * ```
   */
  setRateLimit(
    amount: number,
    frequency: RateLimitFrequency,
    bypassSafeLimit = false,
  ): void {
    MajikAPIValidator.assertPositiveInteger(amount, "amount");

    MajikAPIValidator.assertRateLimitFrequency(frequency, "frequency");

    MajikAPIValidator.assertBoolean(bypassSafeLimit, "bypassSafeLimit");

    MajikAPIValidator.validateRateLimitCeiling(
      amount,
      frequency,
      bypassSafeLimit,
    );

    this._settings.rateLimit = {
      amount,
      frequency,
    };
  }

  /**
   * Restore the default rate-limit configuration.
   *
   * @example
   * ```ts
   * api.resetRateLimit();
   * ```
   */
  resetRateLimit(): void {
    this._settings.rateLimit = {
      ...DEFAULT_RATE_LIMIT,
    };
  }

  // ─────────────────────────────────────────────
  // Quotas
  // ─────────────────────────────────────────────

  /**
   * Configure a fixed, lifetime request quota.
   *
   * Usage is not tracked by MajikAPI itself. The consuming application is
   * responsible for supplying the current usage count to
   * {@link isQuotaExceeded}.
   *
   * @param limit Maximum lifetime request count.
   *
   * @throws {MajikAPIValidationError} When `limit` is not a positive integer.
   *
   * @example
   * ```ts
   * api.setFixedQuota(10_000);
   * ```
   */
  setFixedQuota(limit: number): void {
    MajikAPIValidator.assertPositiveInteger(limit, "limit");

    this._settings.quota = {
      type: "fixed",
      limit,
    };
  }

  /**
   * Configure a recurring quota.
   *
   * The consuming application is responsible for determining the current
   * usage within the relevant period.
   *
   * @param limit Maximum requests allowed per period.
   * @param frequency Recurring quota period.
   *
   * @throws {MajikAPIValidationError} When the limit or frequency is invalid.
   *
   * @example
   * ```ts
   * api.setPeriodicQuota(
   *   50_000,
   *   "months",
   * );
   * ```
   */
  setPeriodicQuota(limit: number, frequency: QuotaFrequency): void {
    MajikAPIValidator.assertPositiveInteger(limit, "limit");

    MajikAPIValidator.validateQuotaFrequency(frequency, "frequency");

    this._settings.quota = {
      type: "periodic",
      limit,
      frequency,
    };
  }

  /**
   * Remove all quota restrictions.
   *
   * After calling this method, {@link isQuotaExceeded} always returns
   * `false` for valid usage input.
   *
   * @example
   * ```ts
   * api.clearQuota();
   * ```
   */
  clearQuota(): void {
    this._settings.quota = null;
  }

  /**
   * Determine whether externally tracked usage has reached the configured
   * quota.
   *
   * MajikAPI does not track request usage. `currentUsage` must therefore be
   * supplied by the consuming application.
   *
   * For a fixed quota, supply lifetime usage.
   *
   * For a periodic quota, supply usage for the current quota period.
   *
   * `0` is a valid usage value.
   *
   * @param currentUsage Current externally tracked request count.
   *
   * @returns `true` when usage is greater than or equal to the configured
   * quota limit. Returns `false` when no quota is configured.
   *
   * @throws {MajikAPIValidationError} When `currentUsage` is not a
   * non-negative integer.
   *
   * @example
   * ```ts
   * api.setFixedQuota(1000);
   *
   * api.isQuotaExceeded(999);
   * // false
   *
   * api.isQuotaExceeded(1000);
   * // true
   * ```
   */
  isQuotaExceeded(currentUsage: number): boolean {
    MajikAPI.assertNonNegativeInteger(currentUsage, "currentUsage");

    const quota = this._settings.quota;

    if (!quota) {
      return false;
    }

    return currentUsage >= quota.limit;
  }

  // ─────────────────────────────────────────────
  // IP whitelist
  // ─────────────────────────────────────────────

  /**
   * Enable IP whitelist enforcement.
   *
   * Existing whitelist entries are preserved.
   *
   * @example
   * ```ts
   * api.enableIPWhitelist();
   * ```
   */
  enableIPWhitelist(): void {
    this._settings.ipWhitelist.enabled = true;
  }

  /**
   * Disable IP whitelist enforcement.
   *
   * Existing whitelist entries are preserved and can be re-enabled later.
   *
   * @example
   * ```ts
   * api.disableIPWhitelist();
   * ```
   */
  disableIPWhitelist(): void {
    this._settings.ipWhitelist.enabled = false;
  }

  /**
   * Add an IP address or supported CIDR range to the whitelist.
   *
   * Input is trimmed and validated before insertion.
   *
   * Duplicate entries are ignored.
   *
   * @param ip IP address or supported CIDR range.
   *
   * @throws {MajikAPIValidationError} When the value is empty or invalid.
   *
   * @example
   * ```ts
   * api.addIP("192.168.1.1");
   * api.addIP("10.0.0.0/24");
   * ```
   */
  addIP(ip: string): void {
    const normalized = MajikAPI.normalizeIP(ip);

    MajikAPI.pushUnique(this._settings.ipWhitelist.addresses, normalized);
  }

  /**
   * Remove an IP address or CIDR entry from the whitelist.
   *
   * Removing an entry that does not exist has no effect.
   *
   * @param ip IP address or CIDR range to remove.
   *
   * @throws {MajikAPIValidationError} When `ip` is not a non-empty string.
   */
  removeIP(ip: string): void {
    MajikAPIValidator.assertString(ip, "ip");

    this._settings.ipWhitelist.addresses =
      this._settings.ipWhitelist.addresses.filter(
        (address) => address !== ip.trim(),
      );
  }

  /**
   * Replace the entire IP whitelist.
   *
   * The supplied values are validated, normalized, and deduplicated before
   * being stored.
   *
   * @param addresses IP addresses and/or supported CIDR ranges.
   *
   * @throws {MajikAPIValidationError} When any entry is invalid.
   *
   * @example
   * ```ts
   * api.setIPWhitelist([
   *   "192.168.1.1",
   *   "10.0.0.0/24",
   * ]);
   * ```
   */
  setIPWhitelist(addresses: string[]): void {
    assertStringArray(addresses, "addresses");

    const normalized = addresses.map((ip) => MajikAPI.normalizeIP(ip));

    this._settings.ipWhitelist.addresses = [...new Set(normalized)];
  }

  /**
   * Remove every entry from the IP whitelist.
   *
   * This does not change whether whitelist enforcement is enabled.
   *
   * @example
   * ```ts
   * api.clearIPWhitelist();
   * ```
   */
  clearIPWhitelist(): void {
    this._settings.ipWhitelist.addresses = [];
  }

  // ─────────────────────────────────────────────
  // Domain whitelist
  // ─────────────────────────────────────────────

  /**
   * Enable domain whitelist enforcement.
   *
   * Existing domain entries are preserved.
   */
  enableDomainWhitelist(): void {
    this._settings.domainWhitelist.enabled = true;
  }

  /**
   * Disable domain whitelist enforcement.
   *
   * Existing domain entries remain configured.
   */
  disableDomainWhitelist(): void {
    this._settings.domainWhitelist.enabled = false;
  }

  /**
   * Add a validated domain to the whitelist.
   *
   * Input is trimmed and duplicate entries are ignored.
   *
   * @param domain Domain name to whitelist.
   *
   * @throws {MajikAPIValidationError} When the domain is invalid.
   *
   * @example
   * ```ts
   * api.addDomain(
   *   "api.example.com",
   * );
   * ```
   */
  addDomain(domain: string): void {
    const normalized = MajikAPI.normalizeDomain(domain);

    MajikAPI.pushUnique(this._settings.domainWhitelist.domains, normalized);
  }

  /**
   * Remove a domain from the whitelist.
   *
   * Removing a missing domain has no effect.
   *
   * @param domain Domain to remove.
   *
   * @throws {MajikAPIValidationError} When the value is not a non-empty
   * string.
   */
  removeDomain(domain: string): void {
    MajikAPIValidator.assertString(domain, "domain");

    this._settings.domainWhitelist.domains =
      this._settings.domainWhitelist.domains.filter(
        (value) => value !== domain.trim(),
      );
  }

  /**
   * Replace the entire domain whitelist.
   *
   * Values are validated, normalized, and deduplicated before being stored.
   *
   * @param domains Domains to whitelist.
   *
   * @throws {MajikAPIValidationError} When any domain is invalid.
   */
  setDomainWhitelist(domains: string[]): void {
    assertStringArray(domains, "domains");

    const normalized = domains.map((domain) =>
      MajikAPI.normalizeDomain(domain),
    );

    this._settings.domainWhitelist.domains = [...new Set(normalized)];
  }

  /**
   * Remove every entry from the domain whitelist.
   *
   * This does not disable whitelist enforcement.
   */
  clearDomainWhitelist(): void {
    this._settings.domainWhitelist.domains = [];
  }

  // ─────────────────────────────────────────────
  // Allowed HTTP methods
  // ─────────────────────────────────────────────

  /**
   * Configure the HTTP methods permitted for this API key.
   *
   * Values are:
   *
   * - trimmed
   * - normalized to uppercase
   * - validated against the supported HTTP-method set
   * - deduplicated
   *
   * Supported methods:
   *
   * ```text
   * GET
   * POST
   * PUT
   * PATCH
   * DELETE
   * HEAD
   * OPTIONS
   * ```
   *
   * @param methods HTTP methods to allow.
   *
   * @throws {MajikAPIValidationError} When a method is unknown or invalid.
   *
   * @example
   * ```ts
   * api.setAllowedMethods([
   *   "GET",
   *   "POST",
   *   "PATCH",
   * ]);
   * ```
   */
  setAllowedMethods(methods: string[]): void {
    assertStringArray(methods, "methods");

    const normalized = methods.map((method) => method.trim().toUpperCase());

    for (const method of normalized) {
      if (!VALID_HTTP_METHODS.has(method)) {
        throw new MajikAPIValidationError(
          `Unknown HTTP method "${method}". Valid methods: ${HTTP_METHODS.join(", ")}`,
          "methods",
        );
      }
    }

    this._settings.allowedMethods = [...new Set(normalized)];
  }

  /**
   * Remove all HTTP-method restrictions.
   *
   * After clearing, the `allowedMethods` configuration becomes an empty
   * array.
   */
  clearAllowedMethods(): void {
    this._settings.allowedMethods = [];
  }

  // ─────────────────────────────────────────────
  // Metadata
  // ─────────────────────────────────────────────

  /**
   * Create or update an application-defined metadata value.
   *
   * Metadata keys are trimmed before storage.
   *
   * The value may be any value supported by the surrounding serialization
   * model.
   *
   * @param key Metadata key.
   * @param value Metadata value.
   *
   * @throws {MajikAPIValidationError} When `key` is invalid.
   *
   * @example
   * ```ts
   * api.setMetadata(
   *   "environment",
   *   "production",
   * );
   *
   * api.setMetadata(
   *   "tier",
   *   3,
   * );
   * ```
   */
  setMetadata(key: string, value: unknown): void {
    MajikAPIValidator.assertString(key, "metadata key");

    if (!this._settings.metadata) {
      this._settings.metadata = {};
    }

    this._settings.metadata[key.trim()] = value;
  }

  /**
   * Retrieve a metadata value.
   *
   * Returns `undefined` when the key does not exist.
   *
   * @param key Metadata key.
   *
   * @returns The stored metadata value, or `undefined`.
   *
   * @throws {MajikAPIValidationError} When `key` is invalid.
   */
  getMetadata(key: string): unknown {
    MajikAPIValidator.assertString(key, "metadata key");

    return this._settings.metadata?.[key.trim()];
  }

  /**
   * Delete one metadata field.
   *
   * Removing a missing field has no effect.
   *
   * @param key Metadata key to remove.
   *
   * @throws {MajikAPIValidationError} When `key` is invalid.
   */
  deleteMetadata(key: string): void {
    MajikAPIValidator.assertString(key, "metadata key");

    this._settings.metadata && delete this._settings.metadata[key.trim()];
  }

  /**
   * Remove all metadata.
   *
   * The metadata object is replaced with an empty object.
   */
  clearMetadata(): void {
    this._settings.metadata = {};
  }

  // ─────────────────────────────────────────────
  // Getters
  // ─────────────────────────────────────────────

  /**
   * Stable API-key resource identifier.
   *
   * This value remains unchanged across key rotation.
   *
   * @returns The stable API-key resource ID.
   */
  get id(): string {
    return this._id;
  }

  /**
   * Owner identifier associated with this API key.
   *
   * @returns The configured owner ID.
   */
  get ownerId(): string {
    return this._owner_id;
  }

  /**
   * Human-readable API-key name.
   *
   * @returns The current key name.
   */
  get name(): string {
    return this._name;
  }

  /**
   * SHA-256 digest of the current API credential.
   *
   * This is the credential representation intended for persistent storage.
   *
   * This getter does NOT return plaintext.
   *
   * @returns SHA-256 credential digest.
   */
  get apiKey(): string {
    return this._api_key;
  }

  /**
   * Temporary plaintext API credential.
   *
   * This is populated only after:
   *
   * - `create()`
   * - `rotate()`
   *
   * It is intentionally undefined for instances reconstructed via
   * {@link fromJSON}.
   *
   * Treat the returned value as sensitive credential material.
   *
   * @returns Plaintext API credential when temporarily available,
   * otherwise `undefined`.
   */
  get rawApiKey(): string | undefined {
    return this._raw_api_key;
  }

  /**
   * Return the API-key creation timestamp as a defensive Date copy.
   *
   * The original internal Date object cannot be mutated through this getter.
   *
   * @returns API-key creation timestamp.
   */
  get createdAt(): Date {
    return new Date(this._timestamp);
  }

  /**
   * Return the API-key creation timestamp as an ISO 8601 string.
   *
   * @returns ISO 8601 creation timestamp.
   */
  get timestamp(): string {
    return this._timestamp.toISOString();
  }

  /**
   * Administrative restriction state.
   *
   * @returns `true` when manually restricted.
   */
  get restricted(): boolean {
    return this._restricted;
  }

  /**
   * Return a defensive copy of the expiration timestamp.
   *
   * `null` means the key has no configured expiration.
   *
   * @returns Expiration Date copy or `null`.
   */
  get validUntil(): Date | null {
    return this._valid_until ? new Date(this._valid_until) : null;
  }

  /**
   * Whether the API key is currently active.
   *
   * This is equivalent to `isActive()`.
   *
   * Quota state is intentionally not included.
   *
   * @returns `true` when the key is not restricted and not expired.
   */
  get is_valid(): boolean {
    return this.isActive();
  }

  /**
   * Return a deep defensive copy of the complete settings object.
   *
   * Mutating the returned value does not mutate the API-key instance.
   *
   * @returns Read-only view of API-key settings.
   */
  get settings(): Readonly<MajikAPISettings> {
    return structuredClone(this._settings);
  }

  /**
   * Return the configured rate-limit settings.
   *
   * @returns Defensive copy of the current rate-limit configuration.
   */
  get rateLimit(): Readonly<RateLimit> {
    return {
      ...this._settings.rateLimit,
    };
  }

  /**
   * Return the current quota configuration.
   *
   * `null` represents an unlimited API key.
   *
   * @returns Defensive copy of the quota or `null`.
   */
  get quota(): Readonly<Quota> {
    return this._settings.quota ? structuredClone(this._settings.quota) : null;
  }

  /**
   * Return the currently configured quota limit.
   *
   * This is a convenience accessor equivalent to:
   *
   * ```ts
   * api.quota?.limit ?? null
   * ```
   *
   * @returns Quota limit or `null` when no quota is configured.
   */
  get quotaLimit(): number | null {
    return this._settings.quota?.limit ?? null;
  }

  /**
   * Return the frequency of a periodic quota.
   *
   * Fixed quotas have no frequency and therefore return `null`.
   *
   * @returns Periodic quota frequency or `null`.
   */
  get quotaFrequency(): QuotaFrequency | null {
    return this._settings.quota?.type === "periodic"
      ? this._settings.quota.frequency
      : null;
  }

  /**
   * Return a defensive copy of the IP whitelist configuration.
   *
   * @returns Current IP whitelist state and entries.
   */
  get ipWhitelist(): Readonly<IPWhitelist> {
    return structuredClone(this._settings.ipWhitelist);
  }

  /**
   * Return a defensive copy of the domain whitelist configuration.
   *
   * @returns Current domain whitelist state and entries.
   */
  get domainWhitelist(): Readonly<DomainWhitelist> {
    return structuredClone(this._settings.domainWhitelist);
  }

  /**
   * Return the configured allowed HTTP methods.
   *
   * A fresh array is returned to prevent accidental mutation of internal
   * state.
   *
   * @returns Array of configured HTTP methods.
   */
  get allowedMethods(): string[] {
    return [...(this._settings.allowedMethods ?? [])];
  }

  /**
   * Return the number of milliseconds remaining until expiration.
   *
   * Return values:
   *
   * - `-1` — no expiration is configured.
   * - `0` — the key has already expired.
   * - `> 0` — milliseconds remaining until expiration.
   *
   * The value is calculated dynamically each time the getter is accessed.
   *
   * @returns Milliseconds until expiration.
   */
  get msUntilExpiry(): number {
    if (this._valid_until === null) {
      return -1;
    }

    return Math.max(0, this._valid_until.getTime() - Date.now());
  }

  /**
   * Return the current lifecycle status.
   *
   * Possible values:
   *
   * - `active`
   * - `restricted`
   * - `expired`
   * - `revoked`
   *
   * Status is computed dynamically from the current restriction and
   * expiration state.
   *
   * Revocation takes precedence over the other states.
   *
   * @returns Current lifecycle status.
   */
  get status(): "active" | "restricted" | "expired" | "revoked" {
    if (this._valid_until?.getTime() === REVOKED_TIMESTAMP) {
      return "revoked";
    }

    if (this.isExpired()) {
      return "expired";
    }

    if (this._restricted) {
      return "restricted";
    }

    return "active";
  }

  /**
   * Optional opaque application reference ID.
   *
   * MajikAPI does not interpret the semantic meaning of this value.
   *
   * @returns Application-defined reference ID or `null`.
   */
  get referenceId(): string | null {
    return this._reference_id;
  }

  // ─────────────────────────────────────────────
  // Debug / inspection
  // ─────────────────────────────────────────────

  /**
   * Return a concise human-readable representation of the API-key resource.
   *
   * The representation contains identifying and lifecycle information but
   * intentionally does not expose the plaintext API credential.
   *
   * @returns Human-readable MajikAPI representation.
   */
  toString(): string {
    return (
      `[MajikAPI id="${this._id}" ` +
      `owner="${this._owner_id}" ` +
      `name="${this._name}" ` +
      `status="${this.status}" ` +
      `is_valid=${this.is_valid}]`
    );
  }

  /**
   * Node.js custom inspection handler.
   *
   * Delegates to {@link toString} so debugging an instance does not expose
   * the plaintext API credential.
   *
   * @returns Human-readable inspection representation.
   */
  [Symbol.for("nodejs.util.inspect.custom")](): string {
    return this.toString();
  }

  // ─────────────────────────────────────────────
  // Private helpers
  // ─────────────────────────────────────────────

  /**
   * Resolve a caller-provided plaintext API credential or generate one.
   *
   * Used by both `create()` and `rotate()` to keep credential generation and
   * validation behavior consistent.
   *
   * @param text Optional caller-provided credential.
   * @param operation Name of the public operation requesting the key.
   *
   * @returns A normalized plaintext credential.
   *
   * @throws {MajikAPIValidationError} When a supplied credential is empty or
   * invalid.
   *
   * @private
   */
  private static resolveRawKey(
    text: string | undefined,
    operation: "create" | "rotate",
  ): string {
    if (text === undefined) {
      return generateID();
    }

    MajikAPIValidator.assertString(text, `${operation} text`);

    return text.trim();
  }

  /**
   * Normalize and validate an API-key name.
   *
   * When no name is provided, `"Unnamed Key"` is used.
   *
   * @param name Optional key name.
   *
   * @returns Trimmed, non-empty key name.
   *
   * @throws {MajikAPIValidationError} When the supplied name is invalid.
   *
   * @private
   */
  private static normalizeName(name: string | undefined): string {
    const resolved = name ?? "Unnamed Key";

    MajikAPIValidator.assertString(resolved, "name");

    return resolved.trim();
  }

  /**
   * Normalize an optional string.
   *
   * `null` and `undefined` are represented as `null`.
   *
   * Non-null values are validated and trimmed.
   *
   * @param value Value to normalize.
   * @param field Field name used in validation errors.
   *
   * @returns Trimmed string or `null`.
   *
   * @private
   */
  private static normalizeOptionalString(
    value: unknown,
    field: string,
  ): string | null {
    if (value === null || value === undefined) {
      return null;
    }

    MajikAPIValidator.assertString(value, field);

    return value.trim();
  }

  /**
   * Parse and validate an ISO timestamp loaded from serialized state.
   *
   * This helper is specifically used for persisted data rather than mutable
   * runtime date inputs.
   *
   * @param value Serialized date value.
   * @param field Field name used in validation errors.
   *
   * @returns A valid Date instance.
   *
   * @throws {MajikAPIValidationError} When the value is not a valid ISO date.
   *
   * @private
   */
  private static parseSerializedDate(value: unknown, field: string): Date {
    MajikAPIValidator.assertString(value, field);

    if (!isValidISODate(value)) {
      throw new MajikAPIValidationError(
        `'${field}' is not a valid ISO date.`,
        field,
      );
    }

    const parsed = new Date(value);

    MajikAPI.assertValidDate(parsed, field);

    return parsed;
  }

  /**
   * Build and validate a complete API-key settings object.
   *
   * Partial settings are merged with library defaults by
   * `buildDefaultSettings()`.
   *
   * @param settings Optional partial settings.
   *
   * @returns Fully populated, validated settings.
   *
   * @throws {MajikAPIValidationError} When the resulting settings are invalid.
   *
   * @private
   */
  private static createSettings(
    settings?: Partial<MajikAPISettings>,
  ): MajikAPISettings {
    const resolved = buildDefaultSettings(settings);

    MajikAPI.validateSettings(resolved);

    return resolved;
  }

  /**
   * Validate the complete runtime settings structure.
   *
   * This supplements the generic validation performed by
   * `MajikAPIValidator` with validation specific to nested API-key
   * configuration such as:
   *
   * - IP whitelist contents
   * - domain whitelist contents
   * - allowed HTTP methods
   * - metadata shape
   * - complete rate-limit configuration
   *
   * @param settings Settings object to validate.
   *
   * @throws {MajikAPIValidationError} When any setting is invalid.
   *
   * @private
   */
  private static validateSettings(settings: MajikAPISettings): void {
    MajikAPIValidator.validateSettings(settings);

    if (!settings || typeof settings !== "object" || Array.isArray(settings)) {
      throw new MajikAPIValidationError(
        "'settings' must be a plain object.",
        "settings",
      );
    }

    if (!settings.rateLimit) {
      throw new MajikAPIValidationError(
        "'settings.rateLimit' is required.",
        "settings.rateLimit",
      );
    }

    MajikAPIValidator.assertRateLimitFrequency(
      settings.rateLimit.frequency,
      "frequency",
    );

    if (!settings.ipWhitelist || typeof settings.ipWhitelist !== "object") {
      throw new MajikAPIValidationError(
        "'settings.ipWhitelist' must be an object.",
        "settings.ipWhitelist",
      );
    }

    MajikAPIValidator.assertBoolean(
      settings.ipWhitelist.enabled,
      "settings.ipWhitelist.enabled",
    );

    assertStringArray(
      settings.ipWhitelist.addresses,
      "settings.ipWhitelist.addresses",
    );

    for (const ip of settings.ipWhitelist.addresses) {
      validateIP(ip);
    }

    if (
      !settings.domainWhitelist ||
      typeof settings.domainWhitelist !== "object"
    ) {
      throw new MajikAPIValidationError(
        "'settings.domainWhitelist' must be an object.",
        "settings.domainWhitelist",
      );
    }

    MajikAPIValidator.assertBoolean(
      settings.domainWhitelist.enabled,
      "settings.domainWhitelist.enabled",
    );

    assertStringArray(
      settings.domainWhitelist.domains,
      "settings.domainWhitelist.domains",
    );

    for (const domain of settings.domainWhitelist.domains) {
      validateDomain(domain);
    }

    if (settings.allowedMethods !== undefined) {
      assertStringArray(settings.allowedMethods, "settings.allowedMethods");

      for (const method of settings.allowedMethods) {
        if (!VALID_HTTP_METHODS.has(method.toUpperCase())) {
          throw new MajikAPIValidationError(
            `Unknown HTTP method "${method}".`,
            "settings.allowedMethods",
          );
        }
      }
    }

    if (
      settings.metadata !== undefined &&
      (typeof settings.metadata !== "object" ||
        settings.metadata === null ||
        Array.isArray(settings.metadata))
    ) {
      throw new MajikAPIValidationError(
        "'settings.metadata' must be a plain object.",
        "settings.metadata",
      );
    }

    const quota = settings.quota;

    if (quota?.type === "periodic") {
      MajikAPIValidator.validateQuotaFrequency(
        quota.frequency,
        "settings.quota.frequency",
      );
    }

    if (quota?.type === "fixed") {
      MajikAPIValidator.assertPositiveInteger(
        quota.limit,
        "settings.quota.limit",
      );
    }
  }

  /**
   * Normalize and validate an IP address or CIDR range.
   *
   * @param ip IP address or CIDR range.
   *
   * @returns Trimmed validated IP value.
   *
   * @throws {MajikAPIValidationError} When the value is invalid.
   *
   * @private
   */
  private static normalizeIP(ip: string): string {
    MajikAPIValidator.assertString(ip, "ip");

    const normalized = ip.trim();

    validateIP(normalized);

    return normalized;
  }

  /**
   * Normalize and validate a domain.
   *
   * @param domain Domain name.
   *
   * @returns Trimmed validated domain.
   *
   * @throws {MajikAPIValidationError} When the value is invalid.
   *
   * @private
   */
  private static normalizeDomain(domain: string): string {
    MajikAPIValidator.assertString(domain, "domain");

    const normalized = domain.trim();

    validateDomain(normalized);

    return normalized;
  }

  /**
   * Append a value to an array only when it is not already present.
   *
   * This helper provides deduplication for whitelist entries without
   * changing ordering.
   *
   * @param target Destination array.
   * @param value Value to insert.
   *
   * @private
   */
  private static pushUnique<T>(target: T[], value: T): void {
    if (!target.includes(value)) {
      target.push(value);
    }
  }

  /**
   * Assert that a Date instance is valid.
   *
   * Invalid Date objects are rejected even though they are technically
   * instances of Date.
   *
   * @param value Date to validate.
   * @param field Field name used in validation errors.
   *
   * @throws {MajikAPIValidationError} When the date is invalid.
   *
   * @private
   */
  private static assertValidDate(value: Date, field: string): void {
    if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
      throw new MajikAPIValidationError(
        `'${field}' is not a valid Date.`,
        field,
      );
    }
  }

  /**
   * Validate an externally supplied usage counter.
   *
   * Unlike `assertPositiveInteger`, this intentionally allows zero because
   * zero requests is a valid initial usage state.
   *
   * Valid values are:
   *
   * - `0`
   * - positive integers
   *
   * Invalid values include:
   *
   * - negative numbers
   * - fractional numbers
   * - `NaN`
   * - infinities
   * - strings
   * - null/undefined
   *
   * @param value Usage count.
   * @param field Field name used in validation errors.
   *
   * @throws {MajikAPIValidationError} When the value is invalid.
   *
   * @private
   */
  private static assertNonNegativeInteger(
    value: unknown,
    field: string,
  ): asserts value is number {
    if (typeof value !== "number" || !Number.isInteger(value) || value < 0) {
      throw new MajikAPIValidationError(
        `${field} must be a non-negative integer.`,
        field,
      );
    }
  }
}

// Freeze static methods
Object.freeze(MajikAPI);

// Freeze instance methods
Object.freeze(MajikAPI.prototype);
