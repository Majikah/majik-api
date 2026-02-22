import { hash } from "@stablelib/sha256";
import { v4 as uuidv4 } from "uuid";
import { MajikAPISettings, RateLimitFrequency } from "./types";
import { DEFAULT_RATE_LIMIT } from "./constants";

export function sha256(input: string): string {
  const hashed = hash(new TextEncoder().encode(input));
  return arrayToBase64(hashed);
}

export function arrayToBase64(data: Uint8Array): string {
  let binary = "";
  const bytes = data;
  const len = bytes.byteLength;

  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }

  return btoa(binary);
}

/**
 * Generate a Random v4 UUID
 */
export function generateID(): string {
  try {
    const genID = uuidv4();

    return genID;
  } catch (error) {
    throw new Error(`Failed to generate ID: ${error}`);
  }
}

// ─────────────────────────────────────────────
//  Validation Helpers
// ─────────────────────────────────────────────

export function assertString(
  value: unknown,
  label: string,
): asserts value is string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new TypeError(
      `[MajikAPI] "${label}" must be a non-empty string. Received: ${JSON.stringify(value)}`,
    );
  }
}

export function assertPositiveInteger(
  value: unknown,
  label: string,
): asserts value is number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1) {
    throw new RangeError(
      `[MajikAPI] "${label}" must be a positive integer. Received: ${JSON.stringify(value)}`,
    );
  }
}

export function assertRateLimitFrequency(
  value: unknown,
  label: string,
): asserts value is RateLimitFrequency {
  const valid: RateLimitFrequency[] = ["seconds", "minutes", "hours"];
  if (!valid.includes(value as RateLimitFrequency)) {
    throw new TypeError(
      `[MajikAPI] "${label}" must be one of: ${valid.join(", ")}. Received: ${JSON.stringify(value)}`,
    );
  }
}

export function assertBoolean(
  value: unknown,
  label: string,
): asserts value is boolean {
  if (typeof value !== "boolean") {
    throw new TypeError(
      `[MajikAPI] "${label}" must be a boolean. Received: ${JSON.stringify(value)}`,
    );
  }
}

export function assertStringArray(
  value: unknown,
  label: string,
): asserts value is string[] {
  if (!Array.isArray(value) || value.some((v) => typeof v !== "string")) {
    throw new TypeError(
      `[MajikAPI] "${label}" must be an array of strings. Received: ${JSON.stringify(value)}`,
    );
  }
}

export function isValidIPv4(ip: string): boolean {
  return (
    /^(\d{1,3}\.){3}\d{1,3}$/.test(ip) &&
    ip.split(".").every((o) => parseInt(o) <= 255)
  );
}

export function isValidIPv6(ip: string): boolean {
  return /^[0-9a-fA-F:]+$/.test(ip) && ip.includes(":");
}

export function isValidCIDR(cidr: string): boolean {
  const [ip, prefix] = cidr.split("/");
  if (!prefix) return false;
  const p = parseInt(prefix);
  return (
    (isValidIPv4(ip) && p >= 0 && p <= 32) ||
    (isValidIPv6(ip) && p >= 0 && p <= 128)
  );
}

export function validateIP(ip: string): void {
  if (!isValidIPv4(ip) && !isValidIPv6(ip) && !isValidCIDR(ip)) {
    throw new Error(`[MajikAPI] Invalid IP address or CIDR: "${ip}"`);
  }
}

export function isValidDomain(domain: string): boolean {
  return (
    /^(\*\.)?[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$/.test(
      domain,
    ) || /^\*$/.test(domain)
  );
}

export function validateDomain(domain: string): void {
  if (!isValidDomain(domain)) {
    throw new Error(`[MajikAPI] Invalid domain: "${domain}"`);
  }
}

export function isValidISODate(value: string): boolean {
  const d = new Date(value);
  return !isNaN(d.getTime());
}

// ─────────────────────────────────────────────
//  Default Settings Factory
// ─────────────────────────────────────────────

export function buildDefaultSettings(
  overrides?: Partial<MajikAPISettings>,
): MajikAPISettings {
  return {
    rateLimit: { ...DEFAULT_RATE_LIMIT, ...(overrides?.rateLimit ?? {}) },
    ipWhitelist: {
      enabled: false,
      addresses: [],
      ...(overrides?.ipWhitelist ?? {}),
    },
    domainWhitelist: {
      enabled: false,
      domains: [],
      ...(overrides?.domainWhitelist ?? {}),
    },
    allowedMethods: overrides?.allowedMethods ?? [],
    metadata: overrides?.metadata ?? {},
    quota: overrides?.quota ?? null,
  };
}
