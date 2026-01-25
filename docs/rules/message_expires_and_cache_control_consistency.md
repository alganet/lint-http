<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_expires_and_cache_control_consistency

## Description

If a response includes both an `Expires` header and a `Cache-Control` freshness directive
(such as `max-age`/`s-maxage`) they SHOULD not contradict each other. When both are
present, `Cache-Control` directives take precedence; clearly contradictory values
(e.g., `Cache-Control: no-cache` while `Expires` is in the future) likely indicate
misconfiguration and should be corrected.

## Specifications

- [RFC 9111 §5.3](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.3) — Cache-Control directives override Expires; recipients MUST ignore the Expires header field when max-age/s-maxage is present.
- [RFC 9111 §4.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.2) — Freshness and age calculations using `max-age`, `s-maxage`, and `Expires`.

## Configuration

Minimal example to enable the rule:

```toml
[rules.message_expires_and_cache_control_consistency]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Date: Wed, 21 Oct 2015 07:28:00 GMT
Cache-Control: max-age=3600
Expires: Wed, 21 Oct 2015 08:28:00 GMT

<...>
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Date: Wed, 21 Oct 2015 07:28:00 GMT
Cache-Control: max-age=0
Expires: Wed, 21 Oct 2015 08:28:00 GMT

<...>
```

```http
HTTP/1.1 200 OK
Date: Wed, 21 Oct 2015 07:28:00 GMT
Cache-Control: no-cache
Expires: Wed, 21 Oct 2015 08:28:00 GMT

<...>
```
