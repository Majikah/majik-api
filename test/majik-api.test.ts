import { beforeEach, describe, expect, it, vi } from "vitest";

import { DEFAULT_RATE_LIMIT, MAX_RATE_LIMIT } from "../src/constants";

import {
  MajikAPIError,
  MajikAPIRateLimitError,
  MajikAPIValidationError,
} from "../src/errors";

import { MajikAPI } from "../src/majik-api";

import type { MajikAPIJSON, MajikAPISettings, Quota } from "../src/types";

// ─────────────────────────────────────────────
// Test fixtures
// ─────────────────────────────────────────────

describe("MajikAPI", () => {
  const validOwnerId = "user_123456789";

  const validRawKey = "majik_sec_key_test_abcdef1234567890";

  const rotatedRawKey = "majik_sec_key_rotated_abcdef999999";

  const futureDateISO = "2099-01-01T00:00:00.000Z";

  const futureDate = new Date(futureDateISO);

  const validIP1 = "192.168.1.1";
  const validIP2 = "10.0.0.1";

  const validDomain1 = "example.com";
  const validDomain2 = "api.example.com";

  beforeEach(() => {
    vi.useRealTimers();
  });

  // ─────────────────────────────────────────────
  // Factory: create()
  // ─────────────────────────────────────────────

  describe("create()", () => {
    it("creates an instance with minimal arguments", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(api).toBeInstanceOf(MajikAPI);

      expect(api.id).toEqual(expect.any(String));
      expect(api.ownerId).toBe(validOwnerId);

      expect(api.name).toBe("Unnamed Key");

      expect(api.restricted).toBe(false);
      expect(api.validUntil).toBeNull();

      expect(api.referenceId).toBeNull();

      expect(api.rawApiKey).toEqual(expect.any(String));
      expect(api.apiKey).toEqual(expect.any(String));

      expect(api.rawApiKey).not.toBe(api.apiKey);

      expect(api.timestamp).toEqual(
        expect.stringMatching(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/),
      );

      expect(api.createdAt).toBeInstanceOf(Date);

      expect(api.status).toBe("active");
      expect(api.is_valid).toBe(true);
      expect(api.isActive()).toBe(true);

      expect(api.rateLimit).toEqual(DEFAULT_RATE_LIMIT);

      expect(api.quota).toBeNull();

      expect(api.ipWhitelist.enabled).toBe(false);
      expect(api.ipWhitelist.addresses).toEqual([]);

      expect(api.domainWhitelist.enabled).toBe(false);
      expect(api.domainWhitelist.domains).toEqual([]);

      expect(api.allowedMethods).toEqual([]);
    });

    it("creates an instance using an explicit raw key", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey);

      expect(api.rawApiKey).toBe(validRawKey);
      expect(api.verify(validRawKey)).toBe(true);
    });

    it("trims owner ID and raw key", () => {
      const api = MajikAPI.create(`  ${validOwnerId}  `, `  ${validRawKey}  `);

      expect(api.ownerId).toBe(validOwnerId);
      expect(api.rawApiKey).toBe(validRawKey);
      expect(api.verify(validRawKey)).toBe(true);
    });

    it("applies custom name", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey, {
        name: "Production Gateway",
      });

      expect(api.name).toBe("Production Gateway");
    });

    it("applies custom restriction", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey, {
        restricted: true,
      });

      expect(api.restricted).toBe(true);
      expect(api.status).toBe("restricted");
      expect(api.isActive()).toBe(false);
    });

    it("applies future Date expiry", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey, {
        valid_until: futureDate,
      });

      expect(api.validUntil).toEqual(futureDate);
      expect(api.isExpired()).toBe(false);
    });

    it("applies future ISO expiry", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey, {
        valid_until: futureDateISO,
      });

      expect(api.validUntil?.toISOString()).toBe(futureDateISO);
    });

    it("applies custom reference ID", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey, {
        referenceId: "  organization_42  ",
      });

      expect(api.referenceId).toBe("organization_42");
    });

    it("applies custom rate-limit settings", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey, {
        settings: {
          rateLimit: {
            amount: 200,
            frequency: "minutes",
          },
        },
      });

      expect(api.rateLimit).toEqual({
        amount: 200,
        frequency: "minutes",
      });
    });

    it("applies custom allowed methods", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey, {
        settings: {
          allowedMethods: ["GET", "POST", "DELETE"],
        },
      });

      expect(api.allowedMethods).toEqual(["GET", "POST", "DELETE"]);
    });

    it("applies custom quota", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey, {
        settings: {
          quota: {
            type: "fixed",
            limit: 10_000,
          },
        },
      });

      expect(api.quota).toEqual({
        type: "fixed",
        limit: 10_000,
      });
    });

    it("creates a fully configured instance", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey, {
        name: "Analytics API",
        restricted: true,
        valid_until: futureDateISO,
        referenceId: "org_123",
        settings: {
          rateLimit: {
            amount: 100,
            frequency: "minutes",
          },
          allowedMethods: ["GET", "POST"],
          quota: {
            type: "periodic",
            limit: 50_000,
            frequency: "months",
          },
          ipWhitelist: {
            enabled: true,
            addresses: [validIP1, validIP2],
          },
          domainWhitelist: {
            enabled: true,
            domains: [validDomain1, validDomain2],
          },
        },
      });

      expect(api.name).toBe("Analytics API");

      expect(api.restricted).toBe(true);

      expect(api.validUntil?.toISOString()).toBe(futureDateISO);

      expect(api.referenceId).toBe("org_123");

      expect(api.rateLimit).toEqual({
        amount: 100,
        frequency: "minutes",
      });

      expect(api.quota).toEqual({
        type: "periodic",
        limit: 50_000,
        frequency: "months",
      });

      expect(api.ipWhitelist).toEqual({
        enabled: true,
        addresses: [validIP1, validIP2],
      });

      expect(api.domainWhitelist).toEqual({
        enabled: true,
        domains: [validDomain1, validDomain2],
      });

      expect(api.allowedMethods).toEqual(["GET", "POST"]);

      expect(api.status).toBe("restricted");
    });

    // ─────────────────────────────────────────
    // Invalid input
    // ─────────────────────────────────────────

    it.each(["", "   ", null, undefined])(
      "rejects invalid owner ID: %p",
      (ownerID) => {
        expect(() =>
          // @ts-expect-error deliberate invalid input
          MajikAPI.create(ownerID),
        ).toThrow(MajikAPIValidationError);
      },
    );

    it("rejects numeric owner ID", () => {
      expect(() =>
        // @ts-expect-error deliberate invalid input
        MajikAPI.create(12345),
      ).toThrow(MajikAPIValidationError);
    });

    it("rejects empty explicit raw key", () => {
      expect(() => MajikAPI.create(validOwnerId, "")).toThrow(
        MajikAPIValidationError,
      );
    });

    it("rejects whitespace-only raw key", () => {
      expect(() => MajikAPI.create(validOwnerId, "     ")).toThrow(
        MajikAPIValidationError,
      );
    });

    it("rejects invalid name", () => {
      expect(() =>
        MajikAPI.create(validOwnerId, undefined, {
          name: "",
        }),
      ).toThrow(MajikAPIValidationError);
    });

    it("rejects whitespace-only name", () => {
      expect(() =>
        MajikAPI.create(validOwnerId, undefined, {
          name: "   ",
        }),
      ).toThrow(MajikAPIValidationError);
    });

    it("rejects invalid restricted type", () => {
      expect(() =>
        MajikAPI.create(validOwnerId, undefined, {
          // @ts-expect-error deliberate invalid input
          restricted: "true",
        }),
      ).toThrow(MajikAPIValidationError);
    });

    it("rejects expired valid_until", () => {
      const past = new Date(Date.now() - 1000);

      expect(() =>
        MajikAPI.create(validOwnerId, undefined, {
          valid_until: past,
        }),
      ).toThrow(MajikAPIValidationError);
    });

    it("rejects current valid_until", () => {
      const now = new Date();

      expect(() =>
        MajikAPI.create(validOwnerId, undefined, {
          valid_until: now,
        }),
      ).toThrow(MajikAPIValidationError);
    });

    it("rejects malformed valid_until", () => {
      expect(() =>
        MajikAPI.create(validOwnerId, undefined, {
          valid_until: "not-a-date",
        }),
      ).toThrow(MajikAPIValidationError);
    });

    it("rejects invalid referenceId type", () => {
      expect(() =>
        MajikAPI.create(validOwnerId, undefined, {
          // @ts-expect-error deliberate invalid input
          referenceId: 123,
        }),
      ).toThrow(MajikAPIValidationError);
    });

    it("rejects empty referenceId", () => {
      expect(() =>
        MajikAPI.create(validOwnerId, undefined, {
          referenceId: "",
        }),
      ).toThrow(MajikAPIValidationError);
    });
  });

  // ─────────────────────────────────────────────
  // Serialization
  // ─────────────────────────────────────────────

  describe("serialization", () => {
    it("serializes all persistent fields", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey, {
        name: "Production",
        valid_until: futureDate,
        referenceId: "ref_123",
        restricted: false,
        settings: {
          rateLimit: {
            amount: 100,
            frequency: "minutes",
          },
          allowedMethods: ["GET", "POST"],
        },
      });

      const json = api.toJSON();

      expect(json).toEqual({
        id: api.id,
        owner_id: api.ownerId,
        name: api.name,
        api_key: api.apiKey,
        timestamp: api.timestamp,
        restricted: false,
        valid_until: futureDateISO,
        is_valid: true,
        settings: api.settings,
        reference_id: "ref_123",
      });
    });

    it("never serializes rawApiKey", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey);

      const json = api.toJSON();

      expect(
        (
          json as unknown as {
            rawApiKey?: string;
          }
        ).rawApiKey,
      ).toBeUndefined();

      expect(JSON.stringify(json)).not.toContain(validRawKey);
    });

    it("serializes revoked state as invalid", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey);

      api.revoke();

      const json = api.toJSON();

      expect(json.restricted).toBe(true);
      expect(json.valid_until).toBe("1970-01-01T00:00:00.000Z");
      expect(json.is_valid).toBe(false);
    });

    it("serializes restricted state as invalid", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey);

      api.restrict();

      expect(api.toJSON().is_valid).toBe(false);
    });

    it("serializes expired state as invalid", () => {
      vi.useFakeTimers();

      const start = new Date("2026-01-01T00:00:00.000Z");

      vi.setSystemTime(start);

      const api = MajikAPI.create(validOwnerId, validRawKey, {
        valid_until: new Date(start.getTime() + 1000),
      });

      vi.setSystemTime(new Date(start.getTime() + 2000));

      const json = api.toJSON();

      expect(json.is_valid).toBe(false);
    });
  });

  // ─────────────────────────────────────────────
  // fromJSON()
  // ─────────────────────────────────────────────

  describe("fromJSON()", () => {
    it("reconstructs an instance from toJSON()", () => {
      const source = MajikAPI.create(validOwnerId, validRawKey, {
        name: "Gateway",
        valid_until: futureDate,
        referenceId: "reference_123",
        settings: {
          rateLimit: {
            amount: 200,
            frequency: "minutes",
          },
          quota: {
            type: "periodic",
            limit: 10_000,
            frequency: "days",
          },
          allowedMethods: ["GET", "POST"],
          ipWhitelist: {
            enabled: true,
            addresses: [validIP1],
          },
          domainWhitelist: {
            enabled: true,
            domains: [validDomain1],
          },
        },
      });

      const json = source.toJSON();

      const restored = MajikAPI.fromJSON(json);

      expect(restored.id).toBe(source.id);

      expect(restored.ownerId).toBe(source.ownerId);

      expect(restored.name).toBe(source.name);

      expect(restored.apiKey).toBe(source.apiKey);

      expect(restored.timestamp).toBe(source.timestamp);

      expect(restored.restricted).toBe(source.restricted);

      expect(restored.validUntil?.toISOString()).toBe(
        source.validUntil?.toISOString(),
      );

      expect(restored.referenceId).toBe(source.referenceId);

      expect(restored.settings).toEqual(source.settings);
    });

    it("does not restore plaintext API key", () => {
      const source = MajikAPI.create(validOwnerId, validRawKey);

      const restored = MajikAPI.fromJSON(source.toJSON());

      expect(restored.rawApiKey).toBeUndefined();

      expect(restored.verify(validRawKey)).toBe(true);
    });

    it("restores null referenceId", () => {
      const source = MajikAPI.create(validOwnerId, validRawKey);

      const restored = MajikAPI.fromJSON(source.toJSON());

      expect(restored.referenceId).toBeNull();
    });

    it("restores restricted state", () => {
      const source = MajikAPI.create(validOwnerId, validRawKey, {
        restricted: true,
      });

      const restored = MajikAPI.fromJSON(source.toJSON());

      expect(restored.restricted).toBe(true);

      expect(restored.status).toBe("restricted");
    });

    it("restores revoked state", () => {
      const source = MajikAPI.create(validOwnerId, validRawKey);

      source.revoke();

      const restored = MajikAPI.fromJSON(source.toJSON());

      expect(restored.status).toBe("revoked");

      expect(restored.isActive()).toBe(false);
    });

    it("rejects null input", () => {
      expect(() => MajikAPI.fromJSON(null as unknown as MajikAPIJSON)).toThrow(
        MajikAPIValidationError,
      );
    });

    it("rejects arrays", () => {
      expect(() => MajikAPI.fromJSON([] as unknown as MajikAPIJSON)).toThrow(
        MajikAPIValidationError,
      );
    });

    it("rejects missing id", () => {
      const json = MajikAPI.create(validOwnerId).toJSON();

      delete (json as unknown as Record<string, unknown>).id;

      expect(() => MajikAPI.fromJSON(json)).toThrow(MajikAPIValidationError);
    });

    it("rejects missing owner_id", () => {
      const json = MajikAPI.create(validOwnerId).toJSON();

      delete (json as unknown as Record<string, unknown>).owner_id;

      expect(() => MajikAPI.fromJSON(json)).toThrow(MajikAPIValidationError);
    });

    it("rejects missing name", () => {
      const json = MajikAPI.create(validOwnerId).toJSON();

      delete (json as unknown as Record<string, unknown>).name;

      expect(() => MajikAPI.fromJSON(json)).toThrow(MajikAPIValidationError);
    });

    it("rejects missing api_key", () => {
      const json = MajikAPI.create(validOwnerId).toJSON();

      delete (json as unknown as Record<string, unknown>).api_key;

      expect(() => MajikAPI.fromJSON(json)).toThrow(MajikAPIValidationError);
    });

    it("rejects malformed timestamp", () => {
      const json = MajikAPI.create(validOwnerId).toJSON();

      json.timestamp = "invalid-date";

      expect(() => MajikAPI.fromJSON(json)).toThrow(MajikAPIValidationError);
    });

    it("rejects malformed valid_until", () => {
      const json = MajikAPI.create(validOwnerId).toJSON();

      json.valid_until = "not-valid";

      expect(() => MajikAPI.fromJSON(json)).toThrow(MajikAPIValidationError);
    });

    it("rejects non-object settings", () => {
      const json = MajikAPI.create(validOwnerId).toJSON();

      json.settings = null as never;

      expect(() => MajikAPI.fromJSON(json)).toThrow(MajikAPIValidationError);
    });

    it("rejects array settings", () => {
      const json = MajikAPI.create(validOwnerId).toJSON();

      json.settings = [] as never;

      expect(() => MajikAPI.fromJSON(json)).toThrow(MajikAPIValidationError);
    });

    it("rejects invalid restricted value", () => {
      const json = MajikAPI.create(validOwnerId).toJSON();

      (
        json as unknown as {
          restricted: unknown;
        }
      ).restricted = "false";

      expect(() => MajikAPI.fromJSON(json)).toThrow(MajikAPIValidationError);
    });
  });

  // ─────────────────────────────────────────────
  // Verification
  // ─────────────────────────────────────────────

  describe("verify() / matches()", () => {
    it("returns true for matching raw key", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey);

      expect(api.verify(validRawKey)).toBe(true);
    });

    it("returns false for incorrect raw key", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey);

      expect(api.verify("completely-wrong-key")).toBe(false);
    });

    it("matches() is an alias for verify()", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey);

      expect(api.matches(validRawKey)).toBe(api.verify(validRawKey));

      expect(api.matches("wrong")).toBe(api.verify("wrong"));
    });

    it("trims verification input", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey);

      expect(api.verify(`  ${validRawKey}  `)).toBe(true);
    });

    it("rejects empty verification input", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey);

      expect(() => api.verify("")).toThrow(MajikAPIValidationError);
    });

    it("rejects whitespace-only verification input", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey);

      expect(() => api.verify("   ")).toThrow(MajikAPIValidationError);
    });

    it("rejects non-string verification input", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey);

      expect(() =>
        // @ts-expect-error deliberate invalid input
        api.verify(123),
      ).toThrow(MajikAPIValidationError);
    });
  });

  // ─────────────────────────────────────────────
  // Lifecycle
  // ─────────────────────────────────────────────

  describe("lifecycle", () => {
    it("starts active", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(api.status).toBe("active");
      expect(api.isActive()).toBe(true);
      expect(api.isExpired()).toBe(false);
      expect(api.is_valid).toBe(true);
    });

    it("becomes restricted after restrict()", () => {
      const api = MajikAPI.create(validOwnerId);

      api.restrict();

      expect(api.restricted).toBe(true);
      expect(api.status).toBe("restricted");
      expect(api.isActive()).toBe(false);
      expect(api.is_valid).toBe(false);
    });

    it("becomes active again after unrestrict()", () => {
      const api = MajikAPI.create(validOwnerId);

      api.restrict();
      api.unrestrict();

      expect(api.restricted).toBe(false);
      expect(api.status).toBe("active");
      expect(api.isActive()).toBe(true);
    });

    it("reports expired state after expiry", () => {
      vi.useFakeTimers();

      const start = new Date("2026-01-01T00:00:00.000Z");

      vi.setSystemTime(start);

      const expiry = new Date(start.getTime() + 60_000);

      const api = MajikAPI.create(validOwnerId, validRawKey, {
        valid_until: expiry,
      });

      expect(api.status).toBe("active");
      expect(api.isExpired()).toBe(false);

      vi.setSystemTime(new Date(expiry.getTime() + 1));

      expect(api.isExpired()).toBe(true);
      expect(api.isActive()).toBe(false);
      expect(api.status).toBe("expired");
      expect(api.is_valid).toBe(false);
    });

    it("reports revoked state after revoke()", () => {
      const api = MajikAPI.create(validOwnerId);

      api.revoke();

      expect(api.restricted).toBe(true);
      expect(api.validUntil?.getTime()).toBe(0);

      expect(api.status).toBe("revoked");

      expect(api.isActive()).toBe(false);
      expect(api.isExpired()).toBe(true);
      expect(api.is_valid).toBe(false);
    });

    it("unrestricting a revoked key does not make it active", () => {
      const api = MajikAPI.create(validOwnerId);

      api.revoke();
      api.unrestrict();

      expect(api.restricted).toBe(false);
      expect(api.status).toBe("revoked");
      expect(api.isActive()).toBe(false);
    });

    it("restriction takes precedence over normal active state", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey, {
        valid_until: futureDate,
      });

      api.restrict();

      expect(api.status).toBe("restricted");
    });
  });

  // ─────────────────────────────────────────────
  // Expiry
  // ─────────────────────────────────────────────

  describe("setExpiry()", () => {
    it("accepts Date", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setExpiry(futureDate);

      expect(api.validUntil?.toISOString()).toBe(futureDateISO);
    });

    it("accepts ISO string", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setExpiry(futureDateISO);

      expect(api.validUntil?.toISOString()).toBe(futureDateISO);
    });

    it("clears expiry when null is supplied", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey, {
        valid_until: futureDate,
      });

      api.setExpiry(null);

      expect(api.validUntil).toBeNull();

      expect(api.msUntilExpiry).toBe(-1);
    });

    it("rejects past dates", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(() => api.setExpiry(new Date(Date.now() - 1000))).toThrow(
        MajikAPIValidationError,
      );
    });

    it("rejects invalid Date objects", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(() => api.setExpiry(new Date("invalid"))).toThrow(
        MajikAPIValidationError,
      );
    });

    it("rejects malformed ISO strings", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(() => api.setExpiry("not-a-date")).toThrow(
        MajikAPIValidationError,
      );
    });
  });

  // ─────────────────────────────────────────────
  // msUntilExpiry
  // ─────────────────────────────────────────────

  describe("msUntilExpiry", () => {
    it("returns -1 when there is no expiry", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(api.msUntilExpiry).toBe(-1);
    });

    it("returns remaining milliseconds", () => {
      vi.useFakeTimers();

      const now = new Date("2026-01-01T00:00:00.000Z");

      const expiry = new Date(now.getTime() + 10_000);

      vi.setSystemTime(now);

      const api = MajikAPI.create(validOwnerId, validRawKey, {
        valid_until: expiry,
      });

      expect(api.msUntilExpiry).toBe(10_000);

      vi.advanceTimersByTime(2_500);

      expect(api.msUntilExpiry).toBe(7_500);
    });

    it("returns zero after expiration", () => {
      vi.useFakeTimers();

      const now = new Date("2026-01-01T00:00:00.000Z");

      vi.setSystemTime(now);

      const api = MajikAPI.create(validOwnerId, validRawKey, {
        valid_until: new Date(now.getTime() + 1000),
      });

      vi.advanceTimersByTime(1001);

      expect(api.msUntilExpiry).toBe(0);
    });
  });

  // ─────────────────────────────────────────────
  // Key rotation
  // ─────────────────────────────────────────────

  describe("rotate()", () => {
    it("generates a new raw key", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey);

      const oldHash = api.apiKey;
      const oldId = api.id;

      api.rotate();

      expect(api.rawApiKey).toEqual(expect.any(String));

      expect(api.apiKey).not.toBe(oldHash);

      expect(api.id).toBe(oldId);
    });

    it("invalidates the old key", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey);

      api.rotate(rotatedRawKey);

      expect(api.verify(validRawKey)).toBe(false);

      expect(api.verify(rotatedRawKey)).toBe(true);
    });

    it("supports explicit replacement key", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey);

      api.rotate(rotatedRawKey);

      expect(api.rawApiKey).toBe(rotatedRawKey);
    });

    it("updates only the API key material", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey, {
        name: "Production",
        restricted: true,
        valid_until: futureDate,
        referenceId: "ref_123",
      });

      const before = {
        id: api.id,
        ownerId: api.ownerId,
        name: api.name,
        restricted: api.restricted,
        validUntil: api.validUntil?.toISOString(),
        referenceId: api.referenceId,
        settings: api.settings,
      };

      api.rotate(rotatedRawKey);

      expect(api.id).toBe(before.id);

      expect(api.ownerId).toBe(before.ownerId);

      expect(api.name).toBe(before.name);

      expect(api.restricted).toBe(before.restricted);

      expect(api.validUntil?.toISOString()).toBe(before.validUntil);

      expect(api.referenceId).toBe(before.referenceId);

      expect(api.settings).toEqual(before.settings);
    });

    it("rejects empty replacement key", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey);

      expect(() => api.rotate("")).toThrow(MajikAPIValidationError);
    });

    it("rejects whitespace-only replacement key", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey);

      expect(() => api.rotate("   ")).toThrow(MajikAPIValidationError);
    });

    it("trims explicit replacement key", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey);

      api.rotate(`  ${rotatedRawKey}  `);

      expect(api.rawApiKey).toBe(rotatedRawKey);

      expect(api.verify(rotatedRawKey)).toBe(true);
    });
  });

  // ─────────────────────────────────────────────
  // Metadata
  // ─────────────────────────────────────────────

  describe("rename()", () => {
    it("renames the API key", () => {
      const api = MajikAPI.create(validOwnerId);

      api.rename("Production API");

      expect(api.name).toBe("Production API");
    });

    it("trims name", () => {
      const api = MajikAPI.create(validOwnerId);

      api.rename("  Production API  ");

      expect(api.name).toBe("Production API");
    });

    it("rejects empty name", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(() => api.rename("")).toThrow(MajikAPIValidationError);
    });

    it("rejects whitespace name", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(() => api.rename("   ")).toThrow(MajikAPIValidationError);
    });
  });

  describe("setReferenceId()", () => {
    it("sets a reference ID", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setReferenceId("tenant_123");

      expect(api.referenceId).toBe("tenant_123");
    });

    it("trims a reference ID", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setReferenceId("  tenant_123  ");

      expect(api.referenceId).toBe("tenant_123");
    });

    it("clears reference ID with null", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey, {
        referenceId: "tenant_123",
      });

      api.setReferenceId(null);

      expect(api.referenceId).toBeNull();
    });

    it("rejects empty reference ID", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(() => api.setReferenceId("")).toThrow(MajikAPIValidationError);
    });

    it("rejects invalid reference ID", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(() =>
        // @ts-expect-error deliberate invalid input
        api.setReferenceId(123),
      ).toThrow(MajikAPIValidationError);
    });
  });

  // ─────────────────────────────────────────────
  // Rate limits
  // ─────────────────────────────────────────────

  describe("rate limiting", () => {
    it("starts with DEFAULT_RATE_LIMIT", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(api.rateLimit).toEqual(DEFAULT_RATE_LIMIT);
    });

    it("sets a valid rate limit", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setRateLimit(300, "minutes");

      expect(api.rateLimit).toEqual({
        amount: 300,
        frequency: "minutes",
      });
    });

    it("supports all rate-limit frequencies accepted by the validator", () => {
      const frequencies = ["seconds", "minutes", "hours"] as const;

      const api = MajikAPI.create(validOwnerId);

      for (const frequency of frequencies) {
        expect(() => api.setRateLimit(1, frequency, true)).not.toThrow();
      }
    });

    it("rejects zero amount", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(() => api.setRateLimit(0, "minutes")).toThrow(
        MajikAPIValidationError,
      );
    });

    it("rejects negative amount", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(() => api.setRateLimit(-1, "minutes")).toThrow(
        MajikAPIValidationError,
      );
    });

    it("rejects fractional amount", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(() => api.setRateLimit(1.5, "minutes")).toThrow(
        MajikAPIValidationError,
      );
    });

    it("rejects invalid frequency", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(() =>
        // @ts-expect-error deliberate invalid input
        api.setRateLimit(10, "invalid"),
      ).toThrow();
    });

    it("rejects non-boolean bypass flag", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(() =>
        // @ts-expect-error deliberate invalid input
        api.setRateLimit(10, "minutes", "true"),
      ).toThrow(MajikAPIValidationError);
    });

    it("allows a rate exactly at the ceiling", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(() =>
        api.setRateLimit(MAX_RATE_LIMIT.amount, MAX_RATE_LIMIT.frequency),
      ).not.toThrow();
    });

    it("rejects rates above the ceiling", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(() =>
        api.setRateLimit(MAX_RATE_LIMIT.amount + 1, MAX_RATE_LIMIT.frequency),
      ).toThrow(MajikAPIRateLimitError);
    });

    it("allows above-ceiling rate when bypass is enabled", () => {
      const api = MajikAPI.create(validOwnerId);

      const amount = MAX_RATE_LIMIT.amount + 1000;

      expect(() =>
        api.setRateLimit(amount, MAX_RATE_LIMIT.frequency, true),
      ).not.toThrow();

      expect(api.rateLimit.amount).toBe(amount);
    });

    it("does not mutate the existing limit when validation fails", () => {
      const api = MajikAPI.create(validOwnerId);

      const before = api.rateLimit;

      expect(() =>
        api.setRateLimit(MAX_RATE_LIMIT.amount + 1, MAX_RATE_LIMIT.frequency),
      ).toThrow(MajikAPIRateLimitError);

      expect(api.rateLimit).toEqual(before);
    });

    it("resets to DEFAULT_RATE_LIMIT", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setRateLimit(100, "minutes");

      api.resetRateLimit();

      expect(api.rateLimit).toEqual(DEFAULT_RATE_LIMIT);
    });
  });

  // ─────────────────────────────────────────────
  // Quotas
  // ─────────────────────────────────────────────

  describe("quotas", () => {
    it("starts with unlimited quota", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(api.quota).toBeNull();
      expect(api.quotaLimit).toBeNull();
      expect(api.quotaFrequency).toBeNull();
    });

    it("sets fixed quota", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setFixedQuota(1000);

      expect(api.quota).toEqual({
        type: "fixed",
        limit: 1000,
      });

      expect(api.quotaLimit).toBe(1000);

      expect(api.quotaFrequency).toBeNull();
    });

    it("sets periodic quota", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setPeriodicQuota(5000, "months");

      expect(api.quota).toEqual({
        type: "periodic",
        limit: 5000,
        frequency: "months",
      });

      expect(api.quotaLimit).toBe(5000);

      expect(api.quotaFrequency).toBe("months");
    });

    it.each(["hours", "days", "weeks", "months", "quarters", "years"] as const)(
      "supports periodic quota frequency %s",
      (frequency) => {
        const api = MajikAPI.create(validOwnerId);

        expect(() => api.setPeriodicQuota(100, frequency)).not.toThrow();

        expect(api.quotaFrequency).toBe(frequency);
      },
    );

    it("clears quota", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setFixedQuota(100);

      api.clearQuota();

      expect(api.quota).toBeNull();

      expect(api.quotaLimit).toBeNull();

      expect(api.quotaFrequency).toBeNull();
    });

    it("allows zero usage", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setFixedQuota(100);

      expect(api.isQuotaExceeded(0)).toBe(false);
    });

    it("returns false when quota is unlimited", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(api.isQuotaExceeded(0)).toBe(false);

      expect(api.isQuotaExceeded(1_000_000)).toBe(false);
    });

    it("returns false below fixed quota", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setFixedQuota(100);

      expect(api.isQuotaExceeded(99)).toBe(false);
    });

    it("returns true at fixed quota boundary", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setFixedQuota(100);

      expect(api.isQuotaExceeded(100)).toBe(true);
    });

    it("returns true above fixed quota", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setFixedQuota(100);

      expect(api.isQuotaExceeded(101)).toBe(true);
    });

    it("applies same comparison semantics to periodic quota", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setPeriodicQuota(1000, "days");

      expect(api.isQuotaExceeded(999)).toBe(false);

      expect(api.isQuotaExceeded(1000)).toBe(true);

      expect(api.isQuotaExceeded(1001)).toBe(true);
    });

    it("rejects zero quota limit", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(() => api.setFixedQuota(0)).toThrow(MajikAPIValidationError);
    });

    it("rejects negative quota limit", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(() => api.setFixedQuota(-1)).toThrow(MajikAPIValidationError);
    });

    it("rejects fractional quota limit", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(() => api.setFixedQuota(1.5)).toThrow(MajikAPIValidationError);
    });

    it("rejects invalid periodic frequency", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(() =>
        // @ts-expect-error deliberate invalid input
        api.setPeriodicQuota(100, "invalid"),
      ).toThrow(MajikAPIValidationError);
    });

    it("rejects negative usage", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setFixedQuota(100);

      expect(() => api.isQuotaExceeded(-1)).toThrow(MajikAPIValidationError);
    });

    it("rejects fractional usage", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setFixedQuota(100);

      expect(() => api.isQuotaExceeded(1.5)).toThrow(MajikAPIValidationError);
    });

    it("rejects string usage", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setFixedQuota(100);

      expect(() =>
        // @ts-expect-error deliberate invalid input
        api.isQuotaExceeded("100"),
      ).toThrow(MajikAPIValidationError);
    });
  });

  // ─────────────────────────────────────────────
  // IP whitelist
  // ─────────────────────────────────────────────

  describe("IP whitelist", () => {
    it("starts disabled", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(api.ipWhitelist).toEqual({
        enabled: false,
        addresses: [],
      });
    });

    it("enables whitelist", () => {
      const api = MajikAPI.create(validOwnerId);

      api.enableIPWhitelist();

      expect(api.ipWhitelist.enabled).toBe(true);
    });

    it("disables whitelist", () => {
      const api = MajikAPI.create(validOwnerId);

      api.enableIPWhitelist();
      api.disableIPWhitelist();

      expect(api.ipWhitelist.enabled).toBe(false);
    });

    it("adds IP address", () => {
      const api = MajikAPI.create(validOwnerId);

      api.addIP(validIP1);

      expect(api.ipWhitelist.addresses).toEqual([validIP1]);
    });

    it("trims IP address", () => {
      const api = MajikAPI.create(validOwnerId);

      api.addIP(`  ${validIP1}  `);

      expect(api.ipWhitelist.addresses).toEqual([validIP1]);
    });

    it("does not add duplicate IP", () => {
      const api = MajikAPI.create(validOwnerId);

      api.addIP(validIP1);
      api.addIP(validIP1);

      expect(api.ipWhitelist.addresses).toEqual([validIP1]);
    });

    it("removes an IP", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setIPWhitelist([validIP1, validIP2]);

      api.removeIP(validIP1);

      expect(api.ipWhitelist.addresses).toEqual([validIP2]);
    });

    it("removing missing IP is harmless", () => {
      const api = MajikAPI.create(validOwnerId);

      api.addIP(validIP1);

      expect(() => api.removeIP(validIP2)).not.toThrow();

      expect(api.ipWhitelist.addresses).toEqual([validIP1]);
    });

    it("replaces whitelist with setIPWhitelist()", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setIPWhitelist([validIP1, validIP2]);

      expect(api.ipWhitelist.addresses).toEqual([validIP1, validIP2]);
    });

    it("deduplicates setIPWhitelist()", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setIPWhitelist([validIP1, validIP1, validIP2]);

      expect(api.ipWhitelist.addresses).toEqual([validIP1, validIP2]);
    });

    it("clears IP whitelist", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setIPWhitelist([validIP1, validIP2]);

      api.clearIPWhitelist();

      expect(api.ipWhitelist.addresses).toEqual([]);
    });

    it("rejects invalid IP on add", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(() => api.addIP("not-an-ip")).toThrow();
    });

    it("rejects invalid IP in set", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(() => api.setIPWhitelist([validIP1, "not-an-ip"])).toThrow();
    });

    it("does not partially apply invalid setIPWhitelist()", () => {
      const api = MajikAPI.create(validOwnerId);

      api.addIP(validIP1);

      expect(() => api.setIPWhitelist([validIP2, "invalid"])).toThrow();

      expect(api.ipWhitelist.addresses).toEqual([validIP1]);
    });
  });

  // ─────────────────────────────────────────────
  // Domain whitelist
  // ─────────────────────────────────────────────

  describe("domain whitelist", () => {
    it("starts disabled", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(api.domainWhitelist).toEqual({
        enabled: false,
        domains: [],
      });
    });

    it("enables whitelist", () => {
      const api = MajikAPI.create(validOwnerId);

      api.enableDomainWhitelist();

      expect(api.domainWhitelist.enabled).toBe(true);
    });

    it("disables whitelist", () => {
      const api = MajikAPI.create(validOwnerId);

      api.enableDomainWhitelist();
      api.disableDomainWhitelist();

      expect(api.domainWhitelist.enabled).toBe(false);
    });

    it("adds a domain", () => {
      const api = MajikAPI.create(validOwnerId);

      api.addDomain(validDomain1);

      expect(api.domainWhitelist.domains).toEqual([validDomain1]);
    });

    it("trims domains", () => {
      const api = MajikAPI.create(validOwnerId);

      api.addDomain(`  ${validDomain1}  `);

      expect(api.domainWhitelist.domains).toEqual([validDomain1]);
    });

    it("does not add duplicate domains", () => {
      const api = MajikAPI.create(validOwnerId);

      api.addDomain(validDomain1);

      api.addDomain(validDomain1);

      expect(api.domainWhitelist.domains).toEqual([validDomain1]);
    });

    it("removes a domain", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setDomainWhitelist([validDomain1, validDomain2]);

      api.removeDomain(validDomain1);

      expect(api.domainWhitelist.domains).toEqual([validDomain2]);
    });

    it("removing missing domain is harmless", () => {
      const api = MajikAPI.create(validOwnerId);

      api.addDomain(validDomain1);

      expect(() => api.removeDomain(validDomain2)).not.toThrow();

      expect(api.domainWhitelist.domains).toEqual([validDomain1]);
    });

    it("replaces domains with setDomainWhitelist()", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setDomainWhitelist([validDomain1, validDomain2]);

      expect(api.domainWhitelist.domains).toEqual([validDomain1, validDomain2]);
    });

    it("deduplicates setDomainWhitelist()", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setDomainWhitelist([validDomain1, validDomain1, validDomain2]);

      expect(api.domainWhitelist.domains).toEqual([validDomain1, validDomain2]);
    });

    it("clears domain whitelist", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setDomainWhitelist([validDomain1, validDomain2]);

      api.clearDomainWhitelist();

      expect(api.domainWhitelist.domains).toEqual([]);
    });

    it("rejects invalid domain on add", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(() => api.addDomain("invalid_domain_#")).toThrow();
    });

    it("rejects invalid domain in set", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(() =>
        api.setDomainWhitelist([validDomain1, "http://invalid"]),
      ).toThrow();
    });

    it("does not partially apply invalid setDomainWhitelist()", () => {
      const api = MajikAPI.create(validOwnerId);

      api.addDomain(validDomain1);

      expect(() =>
        api.setDomainWhitelist([validDomain2, "invalid_domain"]),
      ).toThrow();

      expect(api.domainWhitelist.domains).toEqual([validDomain1]);
    });
  });

  // ─────────────────────────────────────────────
  // Allowed methods
  // ─────────────────────────────────────────────

  describe("allowed HTTP methods", () => {
    it("starts empty", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(api.allowedMethods).toEqual([]);
    });

    it("accepts valid HTTP methods", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setAllowedMethods([
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "HEAD",
        "OPTIONS",
      ]);

      expect(api.allowedMethods).toEqual([
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "HEAD",
        "OPTIONS",
      ]);
    });

    it("normalizes method casing", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setAllowedMethods(["get", "post", "Patch"]);

      expect(api.allowedMethods).toEqual(["GET", "POST", "PATCH"]);
    });

    it("trims method values", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setAllowedMethods([" GET ", " POST "]);

      expect(api.allowedMethods).toEqual(["GET", "POST"]);
    });

    it("deduplicates methods", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setAllowedMethods(["GET", "get", "POST", "GET"]);

      expect(api.allowedMethods).toEqual(["GET", "POST"]);
    });

    it("clears methods", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setAllowedMethods(["GET", "POST"]);

      api.clearAllowedMethods();

      expect(api.allowedMethods).toEqual([]);
    });

    it("rejects CONNECT", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(() => api.setAllowedMethods(["CONNECT"])).toThrow(
        MajikAPIValidationError,
      );
    });

    it("rejects TRACE", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(() => api.setAllowedMethods(["TRACE"])).toThrow(
        MajikAPIValidationError,
      );
    });

    it("rejects arbitrary invalid methods", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(() => api.setAllowedMethods(["INVALID"])).toThrow(
        MajikAPIValidationError,
      );
    });

    it("does not partially update when one method is invalid", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setAllowedMethods(["GET"]);

      expect(() => api.setAllowedMethods(["POST", "INVALID"])).toThrow(
        MajikAPIValidationError,
      );

      expect(api.allowedMethods).toEqual(["GET"]);
    });
  });

  // ─────────────────────────────────────────────
  // Metadata
  // ─────────────────────────────────────────────

  describe("metadata", () => {
    it("sets and gets string metadata", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setMetadata("environment", "production");

      expect(api.getMetadata("environment")).toBe("production");
    });

    it("supports numeric metadata", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setMetadata("version", 42);

      expect(api.getMetadata("version")).toBe(42);
    });

    it("supports object metadata", () => {
      const api = MajikAPI.create(validOwnerId);

      const value = {
        beta: true,
        region: "ap-southeast-1",
      };

      api.setMetadata("flags", value);

      expect(api.getMetadata("flags")).toEqual(value);
    });

    it("overwrites existing metadata", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setMetadata("version", 1);

      api.setMetadata("version", 2);

      expect(api.getMetadata("version")).toBe(2);
    });

    it("trims metadata keys", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setMetadata("  env  ", "production");

      expect(api.getMetadata("env")).toBe("production");
    });

    it("deletes metadata", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setMetadata("env", "production");

      api.deleteMetadata("env");

      expect(api.getMetadata("env")).toBeUndefined();
    });

    it("deleting missing metadata is harmless", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(() => api.deleteMetadata("missing")).not.toThrow();
    });

    it("clears all metadata", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setMetadata("env", "production");

      api.setMetadata("version", 1);

      api.clearMetadata();

      expect(api.getMetadata("env")).toBeUndefined();

      expect(api.getMetadata("version")).toBeUndefined();
    });

    it("rejects empty metadata key", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(() => api.setMetadata("", "value")).toThrow(
        MajikAPIValidationError,
      );
    });

    it("rejects invalid metadata key in getMetadata()", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(() =>
        // @ts-expect-error deliberate invalid input
        api.getMetadata(123),
      ).toThrow(MajikAPIValidationError);
    });

    it("rejects invalid metadata key in deleteMetadata()", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(() =>
        api.deleteMetadata(
          // @ts-expect-error deliberate invalid input
          null,
        ),
      ).toThrow(MajikAPIValidationError);
    });
  });

  // ─────────────────────────────────────────────
  // Defensive copies / immutability
  // ─────────────────────────────────────────────

  describe("defensive copies", () => {
    it("returns a defensive copy from settings", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey, {
        settings: {
          rateLimit: {
            amount: 100,
            frequency: "minutes",
          },
        },
      });

      const settings = api.settings as MajikAPISettings;

      settings.rateLimit.amount = 999_999;

      expect(api.rateLimit.amount).toBe(100);
    });

    it("returns a defensive copy from quota", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setPeriodicQuota(100, "days");

      const quota = api.quota as NonNullable<typeof api.quota>;

      (
        quota as {
          limit: number;
        }
      ).limit = 999;

      expect(api.quotaLimit).toBe(100);
    });

    it("returns a defensive copy from IP whitelist", () => {
      const api = MajikAPI.create(validOwnerId);

      api.addIP(validIP1);

      const whitelist = api.ipWhitelist;

      whitelist.addresses.push(validIP2);

      expect(api.ipWhitelist.addresses).toEqual([validIP1]);
    });

    it("returns a defensive copy from domain whitelist", () => {
      const api = MajikAPI.create(validOwnerId);

      api.addDomain(validDomain1);

      const whitelist = api.domainWhitelist;

      whitelist.domains.push(validDomain2);

      expect(api.domainWhitelist.domains).toEqual([validDomain1]);
    });

    it("returns a new Date from validUntil", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey, {
        valid_until: futureDate,
      });

      const expiry = api.validUntil!;

      expiry.setFullYear(1900);

      expect(api.validUntil?.toISOString()).toBe(futureDateISO);
    });

    it("returns a new Date from createdAt", () => {
      const api = MajikAPI.create(validOwnerId);

      const createdAt = api.createdAt;

      const original = api.timestamp;

      createdAt.setFullYear(1900);

      expect(api.timestamp).toBe(original);
    });

    it("returns a cloned settings object in toJSON()", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey, {
        settings: {
          rateLimit: {
            amount: 10,
            frequency: "minutes",
          },
        },
      });

      const json = api.toJSON();

      (json.settings.rateLimit.amount as number) = 999;

      expect(api.rateLimit.amount).toBe(10);
    });
  });

  // ─────────────────────────────────────────────
  // validate()
  // ─────────────────────────────────────────────

  describe("validate()", () => {
    it("passes for a valid instance", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey, {
        name: "Production",
        referenceId: "ref_123",
        valid_until: futureDate,
        settings: {
          rateLimit: {
            amount: 100,
            frequency: "minutes",
          },
          quota: {
            type: "periodic",
            limit: 1000,
            frequency: "days",
          },
          ipWhitelist: {
            enabled: true,
            addresses: [validIP1],
          },
          domainWhitelist: {
            enabled: true,
            domains: [validDomain1],
          },
        },
      });

      expect(() => api.validate()).not.toThrow();
    });

    it("remains valid after common mutations", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey);

      api.rename("Updated");

      api.setReferenceId("ref_1");

      api.setRateLimit(200, "minutes");

      api.setPeriodicQuota(1000, "days");

      api.addIP(validIP1);

      api.addDomain(validDomain1);

      api.setAllowedMethods(["GET", "POST"]);

      api.setMetadata("environment", "production");

      expect(() => api.validate()).not.toThrow();
    });
  });

  // ─────────────────────────────────────────────
  // Getters
  // ─────────────────────────────────────────────

  describe("getters", () => {
    it("exposes id", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(api.id).toEqual(expect.any(String));
    });

    it("exposes ownerId", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(api.ownerId).toBe(validOwnerId);
    });

    it("exposes name", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey, {
        name: "Test",
      });

      expect(api.name).toBe("Test");
    });

    it("exposes apiKey hash but not plaintext through apiKey", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey);

      expect(api.apiKey).not.toBe(validRawKey);

      expect(api.rawApiKey).toBe(validRawKey);
    });

    it("createdAt equals timestamp", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(api.createdAt.toISOString()).toBe(api.timestamp);
    });

    it("returns null for validUntil when never expires", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(api.validUntil).toBeNull();
    });

    it("is_valid mirrors isActive()", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(api.is_valid).toBe(api.isActive());

      api.restrict();

      expect(api.is_valid).toBe(api.isActive());
    });

    it("rateLimit returns a copy", () => {
      const api = MajikAPI.create(validOwnerId);

      const rateLimit = api.rateLimit;
      // @ts-expect-error deliberate invalid input
      rateLimit.amount = 999;

      expect(api.rateLimit.amount).toBe(DEFAULT_RATE_LIMIT.amount);
    });

    it("allowedMethods returns a copy", () => {
      const api = MajikAPI.create(validOwnerId);

      api.setAllowedMethods(["GET"]);

      const methods = api.allowedMethods;

      methods.push("POST");

      expect(api.allowedMethods).toEqual(["GET"]);
    });
  });

  // ─────────────────────────────────────────────
  // toString / inspect
  // ─────────────────────────────────────────────

  describe("inspection", () => {
    it("returns a useful toString()", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey, {
        name: "Production",
      });

      const result = api.toString();

      expect(result).toContain("[MajikAPI");

      expect(result).toContain(`id="${api.id}"`);

      expect(result).toContain(`owner="${api.ownerId}"`);

      expect(result).toContain(`name="Production"`);

      expect(result).toContain('status="active"');

      expect(result).toContain("is_valid=true");
    });

    it("does not expose plaintext API key in toString()", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey);

      expect(api.toString()).not.toContain(validRawKey);
    });

    it("does not expose plaintext API key through inspect()", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey);

      // @ts-expect-error deliberate invalid input
      const inspect = api[Symbol.for("nodejs.util.inspect.custom")];

      const result = inspect.call(api);

      expect(result).not.toContain(validRawKey);

      expect(result).toBe(api.toString());
    });

    it("reflects status changes in toString()", () => {
      const api = MajikAPI.create(validOwnerId);

      expect(api.toString()).toContain('status="active"');

      api.restrict();

      expect(api.toString()).toContain('status="restricted"');

      api.revoke();

      expect(api.toString()).toContain('status="revoked"');
    });
  });

  // ─────────────────────────────────────────────
  // Invariants
  // ─────────────────────────────────────────────

  describe("domain invariants", () => {
    it("id remains stable across rotation", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey);

      const id = api.id;

      api.rotate(rotatedRawKey);

      expect(api.id).toBe(id);
    });

    it("ownerId remains stable across rotation", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey);

      api.rotate(rotatedRawKey);

      expect(api.ownerId).toBe(validOwnerId);
    });

    it("timestamp remains stable across rotation", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey);

      const timestamp = api.timestamp;

      api.rotate(rotatedRawKey);

      expect(api.timestamp).toBe(timestamp);
    });

    it("API hash changes after rotation", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey);

      const before = api.apiKey;

      api.rotate(rotatedRawKey);

      expect(api.apiKey).not.toBe(before);
    });

    it("serialization round-trip preserves identity", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey, {
        name: "Round Trip",
        referenceId: "ref_123",
        valid_until: futureDate,
        settings: {
          rateLimit: {
            amount: 200,
            frequency: "minutes",
          },
          quota: {
            type: "fixed",
            limit: 10_000,
          },
        },
      });

      const restored = MajikAPI.fromJSON(api.toJSON());

      expect(restored.id).toBe(api.id);

      expect(restored.ownerId).toBe(api.ownerId);

      expect(restored.apiKey).toBe(api.apiKey);

      expect(restored.timestamp).toBe(api.timestamp);

      expect(restored.referenceId).toBe(api.referenceId);
    });

    it("serialization round-trip preserves behavior", () => {
      const api = MajikAPI.create(validOwnerId, validRawKey, {
        settings: {
          quota: {
            type: "fixed",
            limit: 100,
          },
        },
      });

      const restored = MajikAPI.fromJSON(api.toJSON());

      expect(restored.verify(validRawKey)).toBe(true);

      expect(restored.isQuotaExceeded(99)).toBe(false);

      expect(restored.isQuotaExceeded(100)).toBe(true);
    });
  });

  // ─────────────────────────────────────────────
  // Error hierarchy
  // ─────────────────────────────────────────────

  describe("error hierarchy", () => {
    it("validation errors extend MajikAPIError", () => {
      const api = MajikAPI.create(validOwnerId);

      let error: unknown;

      try {
        api.rename("");
      } catch (caught) {
        error = caught;
      }

      expect(error).toBeInstanceOf(MajikAPIValidationError);

      expect(error).toBeInstanceOf(MajikAPIError);

      expect(error).toBeInstanceOf(Error);
    });

    it("rate-limit errors extend MajikAPIError", () => {
      const api = MajikAPI.create(validOwnerId);

      let error: unknown;

      try {
        api.setRateLimit(MAX_RATE_LIMIT.amount + 1, MAX_RATE_LIMIT.frequency);
      } catch (caught) {
        error = caught;
      }

      expect(error).toBeInstanceOf(MajikAPIRateLimitError);

      expect(error).toBeInstanceOf(MajikAPIError);

      expect(error).toBeInstanceOf(Error);
    });

    it("validation errors expose the field when supplied", () => {
      const api = MajikAPI.create(validOwnerId);

      let error: unknown;

      try {
        api.rename("");
      } catch (caught) {
        error = caught;
      }

      expect(error).toBeInstanceOf(MajikAPIValidationError);

      expect((error as MajikAPIValidationError).field).toBe("name");
    });
  });
});
