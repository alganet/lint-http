<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Sec Fetch User Value Valid

## Description

Requests that include the `Sec-Fetch-User` request header MUST only include the structured-boolean `true` value (serialized as `?1`) when present. This header is sent by user agents for navigation requests that were triggered by a user activation. Multiple header fields, and any other value, will be flagged as violations.

## Specifications

- [Fetch Metadata §2.4](https://www.w3.org/TR/fetch-metadata/#sec-fetch-user-header): Fetch Metadata (W3C) — `Sec-Fetch-User` header (boolean, serialized as `?1`)
- [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3): Field Order — a sender MUST NOT write multiple field lines of one name, in the headers or the trailers, unless at least one alternative of the field's definition allows the lines to be recombined as a comma-separated list

## Configuration

```toml
[rules.sec_fetch_user_value_valid]
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
