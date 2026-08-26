<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# X Frame Options Value Valid

## Description

The `X-Frame-Options` response header protects content from being embedded in frames by other origins. This rule validates that the header, when present, uses one of the two values in the HTML Standard's conformance ABNF: `DENY` or `SAMEORIGIN` (matched case-insensitively). The `ALLOW-FROM` variant from RFC 7034 is flagged: the HTML Standard supersedes that document, browsers do not implement it, and a resource relying on it is unprotected — use the CSP `frame-ancestors` directive instead. Multiple header occurrences are also rejected.

## Specifications

- [HTML Speculative Loading §7.7](https://html.spec.whatwg.org/multipage/speculative-loading.html#the-x-frame-options-header): Governing definition: conformance ABNF `"DENY" / "SAMEORIGIN"`, case-insensitive processing, `ALLOW-FROM` not to be implemented
- [RFC 7034 §2.1](https://www.rfc-editor.org/rfc/rfc7034.html#section-2.1): Historical definition (including the dropped `ALLOW-FROM` variant); superseded by the HTML Standard

## Configuration

```toml
[rules.x_frame_options_value_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
X-Frame-Options: DENY

...response body...
```

```http
HTTP/1.1 200 OK
X-Frame-Options: SAMEORIGIN

...response body...
```

### ❌ Bad `ALLOW-FROM` is obsolete and not implemented

```http
HTTP/1.1 200 OK
X-Frame-Options: ALLOW-FROM https://example.com/

...response body...
```

### ❌ Bad

```http
HTTP/1.1 200 OK
X-Frame-Options: DENY, SAMEORIGIN

...response body...
```

```http
HTTP/1.1 200 OK
X-Frame-Options: SOMETHINGELSE

...response body...
```
