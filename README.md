# Majik API

[![Developed by Zelijah](https://img.shields.io/badge/Developed%20by-Zelijah-red?logo=github\&logoColor=white)](https://thezelijah.world) [![GitHub Sponsors](https://img.shields.io/github/sponsors/jedlsf?style=plastic\&label=Sponsors)](https://github.com/sponsors/jedlsf) 
[![npm](https://img.shields.io/npm/v/@majikah/majik-api)](https://www.npmjs.com/package/@majikah/majik-api) [![npm downloads](https://img.shields.io/npm/dm/@majikah/majik-api)](https://www.npmjs.com/package/@majikah/majik-api) [![npm bundle size](https://img.shields.io/bundlephobia/min/%40majikah%2Fmajik-api)](https://bundlephobia.com/package/@majikah/majik-api)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) [![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue)](https://www.typescriptlang.org/)

**Majik API** is a TypeScript API-key management library designed for the **Majikah ecosystem**.

It provides a structured domain model for creating, hashing, validating, rotating, restricting, expiring, and managing API keys, with built-in support for:

* SHA-256 API-key hashing
* stable API-key resource identities
* secure one-time plaintext key access
* lifecycle and status management
* rate-limit configuration
* fixed and periodic quotas
* IP whitelisting
* domain whitelisting
* allowed HTTP methods
* arbitrary metadata
* opaque reference IDs
* JSON serialization and hydration
* defensive copies of mutable configuration
* structured validation and error types

Majik API is intentionally independent of any particular database, cache, framework, or API gateway. It can be used with Supabase, Redis, PostgreSQL, server-side applications, API middleware, edge runtimes, or your own persistence layer.

---

## Table of Contents

- [Majik API](#majik-api)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Design Philosophy](#design-philosophy)
    - [Domain-focused](#domain-focused)
    - [Persistence-agnostic](#persistence-agnostic)
    - [Secure by default](#secure-by-default)
    - [Explicit overrides](#explicit-overrides)
    - [Defensive state boundaries](#defensive-state-boundaries)
- [Technical Architecture](#technical-architecture)
  - [API Key Security](#api-key-security)
  - [Stable Resource Identity](#stable-resource-identity)
  - [One-Time Plaintext Access](#one-time-plaintext-access)
  - [Lifecycle Management](#lifecycle-management)
  - [Rate Limits](#rate-limits)
  - [Quotas](#quotas)
    - [Fixed quota](#fixed-quota)
    - [Periodic quota](#periodic-quota)
  - [Validation and Error Handling](#validation-and-error-handling)
  - [Serialization and Hydration](#serialization-and-hydration)
  - [Defensive Copies](#defensive-copies)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Working with an Existing Key](#working-with-an-existing-key)
- [Key Rotation](#key-rotation)
- [Lifecycle Management](#lifecycle-management-1)
  - [Restrict](#restrict)
  - [Unrestrict](#unrestrict)
  - [Expiry](#expiry)
  - [Revoke](#revoke)
- [Rate Limiting](#rate-limiting)
- [Quota Management](#quota-management)
  - [Fixed quota](#fixed-quota-1)
  - [Periodic quota](#periodic-quota-1)
  - [Clear quota](#clear-quota)
- [IP Whitelisting](#ip-whitelisting)
- [Domain Whitelisting](#domain-whitelisting)
- [Allowed HTTP Methods](#allowed-http-methods)
- [Metadata](#metadata)
- [Reference IDs](#reference-ids)
- [Serialization](#serialization)
- [API Reference](#api-reference)
  - [Static Methods](#static-methods)
  - [Getters](#getters)
  - [Key Management](#key-management)
  - [Lifecycle](#lifecycle)
  - [Rate Limits](#rate-limits-1)
  - [Quotas](#quotas-1)
  - [IP Whitelist](#ip-whitelist)
  - [Domain Whitelist](#domain-whitelist)
  - [Allowed Methods](#allowed-methods)
  - [Metadata](#metadata-1)
  - [Validation and Inspection](#validation-and-inspection)
- [Error Types](#error-types)
  - [`MajikAPIError`](#majikapierror)
  - [`MajikAPIValidationError`](#majikapivalidationerror)
  - [`MajikAPIRateLimitError`](#majikapiratelimiterror)
- [Persistence Example](#persistence-example)
- [Security Notes](#security-notes)
  - [Never store `rawApiKey`](#never-store-rawapikey)
  - [API key hashes are still sensitive](#api-key-hashes-are-still-sensitive)
  - [Key rotation](#key-rotation-1)
  - [Rate limiting and quotas](#rate-limiting-and-quotas)
  - [`isActive()` does not include quota](#isactive-does-not-include-quota)
- [Testing](#testing)
- [Contributing](#contributing)
  - [License](#license)
  - [Author](#author)
  - [Contact](#contact)

---

## Overview

Majik API models an API key as a persistent resource rather than treating the plaintext credential itself as the resource identity.

Conceptually:

```text
API Key Resource
│
├── id
├── ownerId
├── name
├── apiKey
│   └── SHA-256 hash
├── rawApiKey
│   └── temporary plaintext value
├── createdAt / timestamp
├── restricted
├── validUntil
├── status
├── referenceId
└── settings
    ├── rateLimit
    ├── quota
    ├── ipWhitelist
    ├── domainWhitelist
    ├── allowedMethods
    └── metadata
```

This separation allows the API key's persistent identity to survive credential rotation while keeping the plaintext credential outside the serialized representation.

---

## Design Philosophy

Majik API is designed around a few principles:

### Domain-focused

`MajikAPI` owns API-key state and API-key behavior. Validation and error construction are separated into dedicated modules rather than embedding every validation concern into the entity itself.

### Persistence-agnostic

Majik API does not require Supabase, Redis, PostgreSQL, Prisma, Drizzle, or any other persistence system.

You decide how and where the serialized representation is stored.

### Secure by default

The library stores the SHA-256 digest of the API key in the object state rather than the plaintext credential.

### Explicit overrides

Potentially dangerous operations, such as exceeding the default rate-limit ceiling, require an explicit opt-in.

### Defensive state boundaries

Mutable configuration exposed through getters is cloned so external callers cannot accidentally mutate the internal state of the `MajikAPI` instance.

---

# Technical Architecture

## API Key Security

When an API key is created or rotated, the plaintext credential is immediately transformed into a SHA-256 digest:

```ts
const api = MajikAPI.create(
  "user_123",
  "my-secret-api-key",
);

console.log(api.apiKey);
// SHA-256 hash

console.log(api.rawApiKey);
// "my-secret-api-key"
```

The persistent `apiKey` property is the hash, not the plaintext credential.

The raw credential is intentionally kept separate:

```ts
api.rawApiKey
```

It is available after `create()` or `rotate()` so that the caller can present or securely store the newly generated credential.

It is **never included in `toJSON()`**.

---

## Stable Resource Identity

Every `MajikAPI` instance has a stable `id` independent of its API-key credential.

```ts
const api = MajikAPI.create(
  "user_123",
  "first-secret",
);

const id = api.id;

api.rotate("second-secret");

console.log(api.id === id);
// true
```

This makes `id` suitable as a stable primary key or foreign-key target in a persistence layer.

A credential rotation changes the authentication secret, but does not create a new API-key resource identity.

---

## One-Time Plaintext Access

The plaintext API key should be treated like a password.

After creation:

```ts
const api = MajikAPI.create(
  "user_123",
);

const plaintext = api.rawApiKey;
```

After serialization and hydration:

```ts
const restored = MajikAPI.fromJSON(
  api.toJSON(),
);

console.log(restored.rawApiKey);
// undefined
```

The serialized representation intentionally excludes the plaintext credential.

Applications should therefore display or securely deliver the plaintext key during the creation/rotation workflow and then discard it.

---

## Lifecycle Management

A key can have several lifecycle states:

| Status       | Meaning                                    |
| ------------ | ------------------------------------------ |
| `active`     | Not restricted and not expired             |
| `restricted` | Manually disabled                          |
| `expired`    | `validUntil` has passed                    |
| `revoked`    | Permanently invalidated through `revoke()` |

The status is computed dynamically.

```ts
api.status;
api.isActive();
api.isExpired();
api.is_valid;
```

Quota state is intentionally **not** included in `isActive()` because quota evaluation requires usage information from an external system.

---

## Rate Limits

Majik API supports configurable request rate limits:

```ts
api.setRateLimit(
  300,
  "minutes",
);
```

The configured rate is checked against the library's safe ceiling.

By default, a request exceeding the configured maximum produces a `MajikAPIRateLimitError`.

For an explicit administrative override:

```ts
api.setRateLimit(
  5000,
  "minutes",
  true,
);
```

The bypass flag is intentionally explicit so callers cannot accidentally bypass the safety limit.

The default and maximum values are exposed through the library constants:

```ts
DEFAULT_RATE_LIMIT
MAX_RATE_LIMIT
```

---

## Quotas

Majik API supports two quota models.

### Fixed quota

A fixed quota applies to lifetime usage:

```ts
api.setFixedQuota(
  10_000,
);
```

### Periodic quota

A periodic quota applies to an externally tracked usage window:

```ts
api.setPeriodicQuota(
  50_000,
  "months",
);
```

Supported periodic frequencies include:

```text
hours
days
weeks
months
quarters
years
```

Majik API does not track usage itself.

Instead:

```ts
api.isQuotaExceeded(currentUsage);
```

compares an externally supplied usage count against the configured quota.

For example:

```ts
api.setFixedQuota(1000);

api.isQuotaExceeded(999);
// false

api.isQuotaExceeded(1000);
// true
```

A usage count of `0` is valid.

---

## Validation and Error Handling

Validation is separated from the core entity through `MajikAPIValidator`.

The library exposes a structured error hierarchy:

```text
Error
└── MajikAPIError
    ├── MajikAPIValidationError
    └── MajikAPIRateLimitError
```

This allows consumers to distinguish different failure categories.

For example:

```ts
try {
  api.setRateLimit(
    10_000,
    "minutes",
  );
} catch (error) {
  if (error instanceof MajikAPIRateLimitError) {
    // Handle rate-limit configuration error
  }
}
```

Validation errors may also include the relevant field:

```ts
if (
  error instanceof MajikAPIValidationError
) {
  console.log(error.field);
}
```

---

## Serialization and Hydration

Majik API provides:

```ts
api.toJSON();
MajikAPI.fromJSON(data);
```

The JSON representation is designed to be safe for database/cache persistence.

Example:

```ts
const record = api.toJSON();
```

The serialized object contains the API-key hash but does not contain the plaintext API key.

Hydration reconstructs the entity:

```ts
const restored = MajikAPI.fromJSON(
  record,
);
```

The reconstructed object remains fully functional:

```ts
restored.verify(
  "client-provided-key",
);

restored.isActive();

restored.isQuotaExceeded(
  currentUsage,
);
```

---

## Defensive Copies

Configuration exposed through the public getters is cloned.

For example:

```ts
const settings = api.settings;

settings.rateLimit.amount = 999999;
```

does not mutate the actual key configuration.

The same principle applies to:

```ts
api.settings
api.quota
api.ipWhitelist
api.domainWhitelist
api.rateLimit
api.allowedMethods
api.validUntil
api.createdAt
```

This keeps the internal domain state controlled by the `MajikAPI` instance itself.

---

# Features

* SHA-256 hashed API-key storage
* Stable resource identity independent of credential rotation
* One-time plaintext credential access
* Key verification
* Secure credential rotation
* Active/restricted/expired/revoked lifecycle states
* Future expiration dates
* Safe rate-limit ceiling
* Explicit rate-limit bypass
* Fixed lifetime quotas
* Periodic quotas
* IPv4/IPv6/CIDR validation
* Domain validation
* Domain whitelist management
* Allowed HTTP method configuration
* Arbitrary metadata
* Opaque reference IDs
* Defensive copies
* Structured validation errors
* Dedicated rate-limit errors
* JSON serialization
* JSON hydration
* Database/cache friendly representation
* TypeScript-first API

---

# Installation

```bash
npm install @majikah/majik-api
```

---

# Quick Start

```ts
import { MajikAPI } from "@majikah/majik-api";

const api = MajikAPI.create(
  "owner_user_id",
  undefined,
  {
    name: "Production API Key",
  },
);

// The plaintext key is available immediately after creation.
const rawKey = api.rawApiKey;

console.log("Provide this key to the consumer:", rawKey);

// Persist only the serialized representation.
const record = api.toJSON();

// Later, reconstruct the API key resource.
const restored = MajikAPI.fromJSON(record);

// Verify a credential supplied by a client.
const valid = restored.verify(
  "key_provided_by_client",
);

console.log(valid);
```

---

# Working with an Existing Key

When loading a record from a database:

```ts
const record = await database.apiKeys.findById(
  apiKeyId,
);

const api = MajikAPI.fromJSON(
  record,
);
```

The plaintext key is not expected to be present in the database record.

Verification can then be performed directly:

```ts
if (!api.verify(clientApiKey)) {
  throw new Error(
    "Invalid API key",
  );
}
```

For production systems, application-level authorization, rate-limit counters, quota counters, and request auditing should be handled by the surrounding API infrastructure.

---

# Key Rotation

Rotate an existing credential:

```ts
api.rotate();
```

or provide an explicit replacement:

```ts
api.rotate(
  "new-application-secret",
);
```

After rotation:

```ts
api.verify(
  "old-key",
);
// false

api.verify(
  "new-application-secret",
);
// true
```

The stable resource identity remains unchanged:

```ts
const id = api.id;

api.rotate();

console.log(
  api.id === id,
);
// true
```

The new plaintext credential is available through:

```ts
api.rawApiKey;
```

Applications should persist the new serialized representation after rotation.

---

# Lifecycle Management

## Restrict

Temporarily disable a key:

```ts
api.restrict();
```

The key becomes:

```ts
api.status;
// "restricted"
```

and:

```ts
api.isActive();
// false
```

## Unrestrict

Re-enable a manually restricted key:

```ts
api.unrestrict();
```

## Expiry

Set an expiration date:

```ts
api.setExpiry(
  new Date(
    "2099-01-01T00:00:00.000Z",
  ),
);
```

ISO strings are also supported:

```ts
api.setExpiry(
  "2099-01-01T00:00:00.000Z",
);
```

Clear expiration:

```ts
api.setExpiry(null);
```

## Revoke

Permanently invalidate the key:

```ts
api.revoke();
```

The key enters the:

```ts
"revoked"
```

state.

---

# Rate Limiting

Configure a rate limit:

```ts
api.setRateLimit(
  100,
  "minutes",
);
```

Inspect it:

```ts
console.log(
  api.rateLimit,
);
```

Restore the default:

```ts
api.resetRateLimit();
```

To explicitly bypass the safe ceiling:

```ts
api.setRateLimit(
  5000,
  "minutes",
  true,
);
```

Only use the bypass intentionally and under application-specific administrative controls.

---

# Quota Management

## Fixed quota

```ts
api.setFixedQuota(
  10_000,
);
```

Inspect:

```ts
api.quota;
api.quotaLimit;
api.quotaFrequency;
```

Check usage:

```ts
if (
  api.isQuotaExceeded(
    currentUsage,
  )
) {
  // quota reached
}
```

## Periodic quota

```ts
api.setPeriodicQuota(
  50_000,
  "months",
);
```

Supported frequencies:

```ts
"hours"
"days"
"weeks"
"months"
"quarters"
"years"
```

## Clear quota

```ts
api.clearQuota();
```

After clearing the quota:

```ts
api.quota;
// null
```

---

# IP Whitelisting

Enable:

```ts
api.enableIPWhitelist();
```

Add addresses:

```ts
api.addIP(
  "192.168.1.1",
);

api.addIP(
  "10.0.0.1",
);
```

The library validates IP addresses and supported CIDR representations through its validation utilities.

Remove an address:

```ts
api.removeIP(
  "192.168.1.1",
);
```

Replace the entire whitelist:

```ts
api.setIPWhitelist([
  "192.168.1.1",
  "10.0.0.1",
]);
```

Clear it:

```ts
api.clearIPWhitelist();
```

Disable the whitelist without removing its entries:

```ts
api.disableIPWhitelist();
```

Inspect:

```ts
api.ipWhitelist;
```

---

# Domain Whitelisting

Enable:

```ts
api.enableDomainWhitelist();
```

Add domains:

```ts
api.addDomain(
  "example.com",
);

api.addDomain(
  "api.example.com",
);
```

Remove a domain:

```ts
api.removeDomain(
  "example.com",
);
```

Replace the whitelist:

```ts
api.setDomainWhitelist([
  "example.com",
  "api.example.com",
]);
```

Clear the whitelist:

```ts
api.clearDomainWhitelist();
```

Disable enforcement:

```ts
api.disableDomainWhitelist();
```

Inspect:

```ts
api.domainWhitelist;
```

Domain validation is delegated to the library's domain-validation utilities.

---

# Allowed HTTP Methods

Configure the methods a key may be used with:

```ts
api.setAllowedMethods([
  "GET",
  "POST",
  "PATCH",
]);
```

Input method names are normalized to uppercase.

Duplicate methods are removed.

Inspect:

```ts
api.allowedMethods;
```

Clear the configuration:

```ts
api.clearAllowedMethods();
```

Supported methods:

```text
GET
POST
PUT
PATCH
DELETE
HEAD
OPTIONS
```

---

# Metadata

Metadata provides arbitrary application-defined values associated with the API key.

```ts
api.setMetadata(
  "environment",
  "production",
);

api.setMetadata(
  "tier",
  3,
);

api.setMetadata(
  "features",
  {
    beta: true,
  },
);
```

Retrieve values:

```ts
api.getMetadata(
  "environment",
);
```

Delete a value:

```ts
api.deleteMetadata(
  "tier",
);
```

Clear all metadata:

```ts
api.clearMetadata();
```

Metadata can be useful for application-specific classification without making Majik API dependent on a particular business model.

---

# Reference IDs

`referenceId` is an opaque application-defined foreign reference.

Majik API does not assign semantic meaning to it.

For example:

```ts
const api = MajikAPI.create(
  "user_123",
  undefined,
  {
    referenceId:
      "organization_456",
  },
);
```

It can later be changed:

```ts
api.setReferenceId(
  "project_789",
);
```

or cleared:

```ts
api.setReferenceId(null);
```

This makes the field suitable for connecting a Majik API key to another entity in your application's domain.

---

# Serialization

Serialize:

```ts
const json = api.toJSON();
```

The result contains persistent state such as:

```ts
{
  id,
  owner_id,
  name,
  api_key,
  timestamp,
  restricted,
  valid_until,
  is_valid,
  settings,
  reference_id,
}
```

The plaintext `rawApiKey` is intentionally excluded.

Reconstruct:

```ts
const restored =
  MajikAPI.fromJSON(json);
```

The reconstructed instance has no plaintext credential:

```ts
restored.rawApiKey;
// undefined
```

but it can still verify credentials because the persisted hash is sufficient:

```ts
restored.verify(
  clientProvidedKey,
);
```

---

# API Reference

## Static Methods

| Method       | Parameters                                                            | Return     | Description                                                                          |
| ------------ | --------------------------------------------------------------------- | ---------- | ------------------------------------------------------------------------------------ |
| `create()`   | `ownerID: string`, `text?: string`, `options?: MajikAPICreateOptions` | `MajikAPI` | Creates a new API-key resource. Generates a key when `text` is omitted.              |
| `fromJSON()` | `data: MajikAPIJSON`                                                  | `MajikAPI` | Reconstructs an API-key resource from serialized state. Plaintext is never restored. |

---

## Getters

| Getter            | Type                                                 | Description                                                          |
| ----------------- | ---------------------------------------------------- | -------------------------------------------------------------------- |
| `id`              | `string`                                             | Stable API-key resource identifier.                                  |
| `ownerId`         | `string`                                             | Identifier of the resource owner.                                    |
| `name`            | `string`                                             | Human-readable key name.                                             |
| `apiKey`          | `string`                                             | SHA-256 hash of the plaintext API key.                               |
| `rawApiKey`       | `string \| undefined`                                | Temporary plaintext credential available after creation or rotation. |
| `createdAt`       | `Date`                                               | Defensive copy of the creation timestamp.                            |
| `timestamp`       | `string`                                             | ISO 8601 creation timestamp.                                         |
| `restricted`      | `boolean`                                            | Whether the key is manually restricted.                              |
| `validUntil`      | `Date \| null`                                       | Expiration date, or `null` for no expiration.                        |
| `is_valid`        | `boolean`                                            | Whether the key is currently active.                                 |
| `settings`        | `Readonly<MajikAPISettings>`                         | Defensive copy of the complete settings object.                      |
| `rateLimit`       | `Readonly<RateLimit>`                                | Configured rate limit.                                               |
| `quota`           | `Readonly<Quota> \| null`                            | Current quota configuration.                                         |
| `quotaLimit`      | `number \| null`                                     | Configured quota limit.                                              |
| `quotaFrequency`  | `QuotaFrequency \| null`                             | Periodic quota frequency, or `null`.                                 |
| `ipWhitelist`     | `Readonly<IPWhitelist>`                              | Defensive copy of IP whitelist configuration.                        |
| `domainWhitelist` | `Readonly<DomainWhitelist>`                          | Defensive copy of domain whitelist configuration.                    |
| `allowedMethods`  | `string[]`                                           | Configured HTTP methods.                                             |
| `msUntilExpiry`   | `number`                                             | Milliseconds until expiry, `-1` for no expiry and `0` once expired.  |
| `status`          | `"active" \| "restricted" \| "expired" \| "revoked"` | Current lifecycle status.                                            |
| `referenceId`     | `string \| null`                                     | Optional opaque application reference.                               |

---

## Key Management

| Method             | Parameters                    | Return    | Description                                           |
| ------------------ | ----------------------------- | --------- | ----------------------------------------------------- |
| `verify()`         | `text: string`                | `boolean` | Hashes and verifies an incoming plaintext credential. |
| `matches()`        | `text: string`                | `boolean` | Alias for `verify()`.                                 |
| `rotate()`         | `text?: string`               | `void`    | Replaces the current API credential.                  |
| `rename()`         | `name: string`                | `void`    | Changes the key name.                                 |
| `setReferenceId()` | `referenceId: string \| null` | `void`    | Sets or clears the application reference ID.          |

---

## Lifecycle

| Method         | Parameters               | Return    | Description                                                  |
| -------------- | ------------------------ | --------- | ------------------------------------------------------------ |
| `isExpired()`  | none                     | `boolean` | Checks whether the expiration date has passed.               |
| `isActive()`   | none                     | `boolean` | Returns true when the key is not restricted and not expired. |
| `restrict()`   | none                     | `void`    | Manually disables the key.                                   |
| `unrestrict()` | none                     | `void`    | Removes a manual restriction.                                |
| `setExpiry()`  | `Date \| string \| null` | `void`    | Sets or clears expiration.                                   |
| `revoke()`     | none                     | `void`    | Permanently invalidates the key.                             |

---

## Rate Limits

| Method             | Parameters                                                                     | Return | Description                    |
| ------------------ | ------------------------------------------------------------------------------ | ------ | ------------------------------ |
| `setRateLimit()`   | `amount: number`, `frequency: RateLimitFrequency`, `bypassSafeLimit?: boolean` | `void` | Configures a request rate.     |
| `resetRateLimit()` | none                                                                           | `void` | Restores `DEFAULT_RATE_LIMIT`. |

---

## Quotas

| Method               | Parameters                                   | Return    | Description                                                     |
| -------------------- | -------------------------------------------- | --------- | --------------------------------------------------------------- |
| `setFixedQuota()`    | `limit: number`                              | `void`    | Sets a lifetime quota.                                          |
| `setPeriodicQuota()` | `limit: number`, `frequency: QuotaFrequency` | `void`    | Sets a periodic quota.                                          |
| `clearQuota()`       | none                                         | `void`    | Removes quota restrictions.                                     |
| `isQuotaExceeded()`  | `currentUsage: number`                       | `boolean` | Compares externally tracked usage against the configured quota. |

---

## IP Whitelist

| Method                 | Parameters            | Return | Description                        |
| ---------------------- | --------------------- | ------ | ---------------------------------- |
| `enableIPWhitelist()`  | none                  | `void` | Enables IP whitelist enforcement.  |
| `disableIPWhitelist()` | none                  | `void` | Disables IP whitelist enforcement. |
| `addIP()`              | `ip: string`          | `void` | Adds a validated IP/CIDR entry.    |
| `removeIP()`           | `ip: string`          | `void` | Removes an IP/CIDR entry.          |
| `setIPWhitelist()`     | `addresses: string[]` | `void` | Replaces the whitelist.            |
| `clearIPWhitelist()`   | none                  | `void` | Removes all whitelist entries.     |

---

## Domain Whitelist

| Method                     | Parameters          | Return | Description                            |
| -------------------------- | ------------------- | ------ | -------------------------------------- |
| `enableDomainWhitelist()`  | none                | `void` | Enables domain whitelist enforcement.  |
| `disableDomainWhitelist()` | none                | `void` | Disables domain whitelist enforcement. |
| `addDomain()`              | `domain: string`    | `void` | Adds a validated domain.               |
| `removeDomain()`           | `domain: string`    | `void` | Removes a domain.                      |
| `setDomainWhitelist()`     | `domains: string[]` | `void` | Replaces the domain whitelist.         |
| `clearDomainWhitelist()`   | none                | `void` | Removes all domain entries.            |

---

## Allowed Methods

| Method                  | Parameters          | Return | Description                                 |
| ----------------------- | ------------------- | ------ | ------------------------------------------- |
| `setAllowedMethods()`   | `methods: string[]` | `void` | Sets and normalizes supported HTTP methods. |
| `clearAllowedMethods()` | none                | `void` | Removes method restrictions.                |

Supported methods:

```text
GET
POST
PUT
PATCH
DELETE
HEAD
OPTIONS
```

---

## Metadata

| Method             | Parameters                      | Return    | Description                  |
| ------------------ | ------------------------------- | --------- | ---------------------------- |
| `setMetadata()`    | `key: string`, `value: unknown` | `void`    | Creates or updates metadata. |
| `getMetadata()`    | `key: string`                   | `unknown` | Retrieves metadata.          |
| `deleteMetadata()` | `key: string`                   | `void`    | Deletes one metadata field.  |
| `clearMetadata()`  | none                            | `void`    | Removes all metadata.        |

---

## Validation and Inspection

| Method       | Return         | Description                                                               |
| ------------ | -------------- | ------------------------------------------------------------------------- |
| `validate()` | `void`         | Validates the integrity of the current instance.                          |
| `toJSON()`   | `MajikAPIJSON` | Produces a persistence-safe serialized representation.                    |
| `toString()` | `string`       | Produces a human-readable debug representation without plaintext secrets. |

Node.js inspection is also supported through:

```ts
Symbol.for(
  "nodejs.util.inspect.custom",
)
```

---

# Error Types

Majik API exposes a small structured error hierarchy.

## `MajikAPIError`

Base error for Majik API failures.

```ts
class MajikAPIError extends Error {
  cause?: unknown;
}
```

## `MajikAPIValidationError`

Thrown when an input or API-key configuration fails validation.

```ts
class MajikAPIValidationError
  extends MajikAPIError {
  field?: string;
}
```

The optional `field` property identifies the associated input field.

## `MajikAPIRateLimitError`

Thrown when a requested rate exceeds the configured safe ceiling.

```ts
class MajikAPIRateLimitError
  extends MajikAPIError {}
```

Example:

```ts
import {
  MajikAPIRateLimitError,
} from "@majikah/majik-api";

try {
  api.setRateLimit(
    10_000,
    "minutes",
  );
} catch (error) {
  if (
    error instanceof MajikAPIRateLimitError
  ) {
    console.error(
      "Rate limit exceeds safe ceiling",
    );
  }
}
```

---

# Persistence Example

Majik API is intentionally persistence-agnostic.

A typical database integration can look like:

```ts
// Create
const api = MajikAPI.create(
  ownerId,
  undefined,
  {
    name: "Production",
    referenceId: organizationId,
  },
);

// Show/store the plaintext credential securely.
const plaintext = api.rawApiKey;

// Persist the serialized resource.
await database.apiKeys.insert(
  api.toJSON(),
);
```

Later:

```ts
const record =
  await database.apiKeys.findByHash(
    sha256(clientProvidedKey),
  );

if (!record) {
  // Invalid credential
}

const api =
  MajikAPI.fromJSON(record);

if (!api.isActive()) {
  // Disabled / expired credential
}

if (!api.verify(clientProvidedKey)) {
  // Invalid credential
}
```

In an actual API gateway, you would normally combine the entity with external systems responsible for:

* request counters
* distributed rate limiting
* quota counters
* audit/event logging
* IP/network policy enforcement
* database access
* cache invalidation
* authorization

Majik API provides the API-key domain model and configuration; it does not attempt to become the entire API gateway.

---

# Security Notes

## Never store `rawApiKey`

The plaintext API key should be treated as a credential.

Do not persist:

```ts
api.rawApiKey
```

in your database or cache.

Persist:

```ts
api.toJSON();
```

instead.

---

## API key hashes are still sensitive

Although Majik API stores a SHA-256 digest instead of plaintext, the resulting hash is still authentication-related security material.

Protect database access appropriately.

---

## Key rotation

Rotation changes the authentication secret while preserving the resource identity.

After rotating:

```ts
api.rotate();
```

applications should persist the updated serialized record.

Any cache entry keyed by the old credential/hash should be invalidated by the surrounding infrastructure.

---

## Rate limiting and quotas

Majik API does not maintain distributed counters itself.

For horizontally scaled systems, use an external counter or rate-limit service such as Redis or another centralized datastore.

---

## `isActive()` does not include quota

A key may be technically active while its configured quota has been exhausted.

Use:

```ts
api.isActive();
api.isQuotaExceeded(
  currentUsage,
);
```

as separate checks.

---

# Testing

Majik API is designed to be tested as a deterministic domain model.

The test suite covers:

* creation and defaults
* custom configuration
* invalid inputs
* JSON serialization
* JSON hydration
* plaintext-secret exclusion
* credential verification
* credential rotation
* lifecycle transitions
* expiry behavior
* rate-limit boundaries
* rate-limit bypass
* fixed quotas
* periodic quotas
* zero-usage handling
* IP whitelist management
* domain whitelist management
* HTTP method normalization
* metadata CRUD
* reference IDs
* defensive copies
* validation
* status inspection
* error inheritance
* domain invariants
* serialization round trips

Run the project's Vitest suite with:

```bash
npm test
```

or, depending on your package scripts:

```bash
npx vitest run
```

---

# Contributing

Contributions, bug reports, testing improvements, documentation updates, and feature proposals are welcome.

When extending Majik API, prefer keeping responsibilities separated:

```text
majik-api.ts
    ↓
Domain behavior and state

validator.ts
    ↓
Input and configuration validation

errors.ts
    ↓
Structured error hierarchy

utils.ts
    ↓
Generic utility functions

constants.ts
    ↓
Library-wide constants
```

New functionality should ideally include unit tests covering both valid and invalid behavior.

---

## License

[Apache-2.0](LICENSE) — free for personal and commercial use.

---

## Author

Developed by **Josef Elijah Fabian (Zelijah)** | [Majikah Solutions OPC](https://majikah.solutions/about)

**Developer**: [Josef Elijah Fabian](https://github.com/jedlsf)
**GitHub**: [https://github.com/Majikah](https://github.com/Majikah)
**Project Repository**: [https://github.com/Majikah/majik-signature](https://github.com/Majikah/majik-signature)

---

## Contact

- **Business Email**: [business@majikah.solutions](mailto:business@majikah.solutions)
- **Official Website**: [https://www.thezelijah.world](https://www.thezelijah.world)
- **Majikah Ecosystem**: [https://majikah.solutions](https://majikah.solutions)
