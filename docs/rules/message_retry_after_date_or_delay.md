<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Retry-After Date or Delay

## Description

The `Retry-After` header, when present in responses, MUST be either a non-negative integer (delay-seconds) or an HTTP-date (IMF-fixdate). This rule flags `Retry-After` values that do not match either form.

## Specifications

- [RFC 9110 §10.2.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.3): Retry-After header

## Configuration

```toml
[rules.message_retry_after_date_or_delay]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 503 Service Unavailable
Retry-After: 120

HTTP/1.1 503 Service Unavailable
Retry-After: Wed, 21 Oct 2015 07:28:00 GMT
```

### ❌ Bad

```http
HTTP/1.1 503 Service Unavailable
Retry-After: tomorrow

HTTP/1.1 503 Service Unavailable
Retry-After: -1
```