<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_early_data_header_safe_method

Validate that `Early-Data: 1` appears only on safe HTTP methods. `Early-Data` (RFC 8470) is used to indicate TLS 1.3 0-RTT early data; it should only be present on safe methods that are side-effect free (GET, HEAD, OPTIONS, TRACE).

## Description

If a request includes `Early-Data: 1`, the request method must be one of the safe methods: `GET`, `HEAD`, `OPTIONS`, or `TRACE`. Presence of `Early-Data: 1` on non-safe methods such as `POST`, `PUT`, or `DELETE` may indicate misuse of early data and is flagged as a violation.

## Specifications

- [RFC 8470 §4 — Using Early Data in HTTP Clients](https://www.rfc-editor.org/rfc/rfc8470.html#section-4) — Clients MUST NOT send unsafe methods (or methods whose safety is unknown) in early data.
- [RFC 8470 §5.1 — The Early-Data Header Field](https://www.rfc-editor.org/rfc/rfc8470.html#section-5.1) — The `Early-Data` header field has the single valid value `"1"` and indicates the request may have been sent in early data.

## Configuration

```toml
[rules.message_early_data_header_safe_method]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
GET /resource HTTP/1.1
Host: example
Early-Data: 1
```

### ❌ Bad

```http
POST /submit HTTP/1.1
Host: example
Early-Data: 1
```
