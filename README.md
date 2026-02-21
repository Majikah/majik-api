# Majik API

[![Developed by Zelijah](https://img.shields.io/badge/Developed%20by-Zelijah-red?logo=github&logoColor=white)](https://thezelijah.world) ![GitHub Sponsors](https://img.shields.io/github/sponsors/jedlsf?style=plastic&label=Sponsors&link=https%3A%2F%2Fgithub.com%2Fsponsors%2Fjedlsf)

**Majik API** is an API key management library designed for the Majikah ecosystem. It provides a robust, developer-friendly interface for creating, hashing, and managing API keys with built-in support for rate limiting, IP/Domain whitelisting, and secure rotation.

![npm](https://img.shields.io/npm/v/@majikah/majik-api) ![npm downloads](https://img.shields.io/npm/dm/@majikah/majik-api) ![npm bundle size](https://img.shields.io/bundlephobia/min/%40majikah%2Fmajik-api) [![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) ![TypeScript](https://img.shields.io/badge/TypeScript-Ready-blue)



---
- [Majik API](#majik-api)
  - [Technical Architecture](#technical-architecture)
    - [1. Security via SHA-256 Hashing](#1-security-via-sha-256-hashing)
    - [2. Identity Persistence (UUID)](#2-identity-persistence-uuid)
    - [3. Rate Limit Enforcement](#3-rate-limit-enforcement)
  - [Features](#features)
  - [Installation](#installation)
  - [Quick Start](#quick-start)
  - [API Reference](#api-reference)
    - [Instance Getters](#instance-getters)
    - [Static Methods](#static-methods)
    - [Instance Methods: Key Management](#instance-methods-key-management)
    - [Instance Methods: Constraints \& Whitelisting](#instance-methods-constraints--whitelisting)
  - [Contributing](#contributing)
  - [License](#license)
  - [Author](#author)
  - [About the Developer](#about-the-developer)
  - [Contact](#contact)




---
## Technical Architecture

### 1. Security via SHA-256 Hashing
The library ensures that the raw plaintext API key is never stored within the permanent state of the object. Upon creation or rotation, the key is immediately hashed using SHA-256. The rawApiKey property is a temporary field provided only during the initial generation/rotation event to allow for one-time display to the user.

### 2. Identity Persistence (UUID)
Each key instance maintains a stable id (UUIDv4). This ID remains constant even if the API key text is rotated, allowing for consistent Foreign Key relationships in databases (like Supabase) or audit logs.

### 3. Rate Limit Enforcement
The class includes built-in logic to normalize and validate rate limits. It enforces a "Safe Limit" ceiling of 500 requests per minute by default. Any attempt to set a limit higher than this requires an explicit bypassSafeLimit flag.

---

## Features

- **Automated Lifecycle**: Manage active, restricted, and expired statuses automatically based on timestamps and boolean flags.

- **IP Whitelisting**: Supports individual IP addresses and CIDR notation validation.

- **Domain Whitelisting**: Validates domains with support for wildcard (*) subdomains.

- **Status Calculation**: Dynamic status getter that evaluates if a key is revoked, expired, or active.

- **JSON Serialization**: Methods to export/import the class state for database storage (storing only hashes, never raw keys).

---


## Installation

```bash
# Using npm
npm install @majikah/majik-api

```

---

## Quick Start

```ts
import { MajikAPI } from '@majikah/majik-api';

// Create a new key for a specific owner
const key = MajikAPI.create('owner_user_id', undefined, {
  name: 'Production Environment Key'
});

// Capture the raw key once (it won't be in the object after serialization)
console.log('Provide this to user:', key.rawApiKey);

// Save to DB (this only saves the SHA-256 hash)
const data = key.toJSON();
// ... save data to your database ...

// Verifying a request later
const isValid = key.verify('key_provided_by_client'); // returns boolean


```

---

## API Reference


### Instance Getters

| Property | Type | Description |
| :--- | :--- | :--- |
| `id` | `string` | The stable UUIDv4 identifier for the record. |
| `ownerId` | `string` | The identifier of the key owner (e.g., a user ID). |
| `name` | `string` | Human-readable label for the API key. |
| `apiKey` | `string` | The **SHA-256 hash** of the API key. |
| `rawApiKey` | `string \| undefined` | The plaintext key. Only populated immediately after `create()` or `rotate()`. |
| `timestamp` | `string` | ISO 8601 string of the last rotation or creation time. |
| `restricted` | `boolean` | Manual toggle indicating if the key is administratively disabled. |
| `validUntil` | `string \| null` | ISO 8601 expiration date, or `null` if the key never expires. |
| `settings` | `MajikAPISettings` | A structured clone of the key's rate limits and whitelist configurations. |
| `status` | `'revoked' \| 'expired' \| 'active'` | Returns the current operational state based on internal flags and time. |
| `msUntilExpiry` | `number` | Milliseconds remaining until `validUntil`. Returns `-1` if no expiry is set. |

---

### Static Methods

| Method | Parameters | Return Type | Description |
| :--- | :--- | :--- | :--- |
| `create` | `ownerID: string`, `text?: string`, `options?: MajikAPICreateOptions` | `MajikAPI` | Instantiates a new key. Generates a random UUID as the key if `text` is omitted. |
| `fromJSON` | `json: MajikAPIJSON` | `MajikAPI` | Reconstructs an instance from a serialized data object. |

---

### Instance Methods: Key Management

| Method | Parameters | Return Type | Description |
| :--- | :--- | :--- | :--- |
| `verify` | `text: string` | `boolean` | Hashes the input string and performs a constant-time comparison against the stored hash. |
| `rotate` | `text?: string` | `void` | Generates a new hash and updates the timestamp. Populates `rawApiKey` with the new plaintext. |
| `revoke` | *None* | `void` | Permanently disables the key by setting `restricted` to `true` and the expiry to `1970-01-01`. |
| `isActive` | *None* | `boolean` | Returns `true` if the key is not restricted and not expired. |
| `setName` | `name: string` | `void` | Updates the human-readable label. |
| `setRestricted` | `restricted: boolean` | `void` | Manually enables or disables the key. |
| `toJSON` | *None* | `MajikAPIJSON` | Serializes the instance into a plain object for database storage. |

---

### Instance Methods: Constraints & Whitelisting

| Method | Parameters | Return Type | Description |
| :--- | :--- | :--- | :--- |
| `setExpiry` | `date: Date \| string \| null` | `void` | Updates the `valid_until` property. Accepts Date objects or ISO strings. |
| `setRateLimit` | `amount: number`, `freq: RateLimitFrequency`, `bypass?: boolean` | `void` | Sets requests per window. Caps at 500 req/min unless `bypassSafeLimit` is true. |
| `enableIPWhitelist` | *None* | `void` | Enables the IP restriction check. |
| `disableIPWhitelist` | *None* | `void` | Disables the IP restriction check. |
| `addIP` | `ip: string` | `void` | Adds an IPv4, IPv6, or CIDR range to the whitelist. |
| `removeIP` | `ip: string` | `void` | Removes a specific IP/range from the whitelist. |
| `enableDomainWhitelist`| *None* | `void` | Enables the Domain restriction check. |
| `disableDomainWhitelist`| *None* | `void` | Disables the Domain restriction check. |
| `addDomain` | `domain: string` | `void` | Adds a domain (supports `*.example.com` wildcards) to the whitelist. |
| `removeDomain` | `domain: string` | `void` | Removes a specific domain from the whitelist. |

---

## Contributing

If you want to contribute or help extend support to more platforms, reach out via email. All contributions are welcome!  

---

## License

[Apache-2.0](LICENSE) — free for personal and commercial use.

---
## Author

Made with 💙 by [@thezelijah](https://github.com/jedlsf)

## About the Developer

- **Developer**: Josef Elijah Fabian
- **GitHub**: [https://github.com/jedlsf](https://github.com/jedlsf)
- **Project Repository**: [https://github.com/Majikah/majik-api](https://github.com/Majikah/majik-api)

---

## Contact

- **Business Email**: [business@thezelijah.world](mailto:business@thezelijah.world)
- **Official Website**: [https://www.thezelijah.world](https://www.thezelijah.world)
