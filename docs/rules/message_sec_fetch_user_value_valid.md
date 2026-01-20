<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_sec_fetch_user_value_valid

## Description

Requests that include the `Sec-Fetch-User` request header MUST only include the structured-boolean `true` value (serialized as `?1`) when present. This header is sent by user agents for navigation requests that were triggered by a user activation. Multiple header fields or non-ASCII values will be flagged as violations.

## Specifications

- Fetch Metadata (W3C) — `Sec-Fetch-User` header (boolean, serialized as `?1`): https://www.w3.org/TR/fetch-metadata/#sec-fetch-user-header

## Configuration

```toml
[rules.message_sec_fetch_user_value_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Sec-Fetch-User: ?1
```

```http
Sec-Fetch-User:  ?1  # whitespace is allowed and trimmed
```

### ❌ Bad

```http
Sec-Fetch-User: true
```

```http
Sec-Fetch-User:
```

```http
Sec-Fetch-User: 1
```
