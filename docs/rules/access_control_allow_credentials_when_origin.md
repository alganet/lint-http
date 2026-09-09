<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Access-Control Allow Credentials When Origin

## Description

This rule reads the Cross-Origin Resource Sharing (CORS) response headers that decide whether a response may be shared with credentials, and asks two things.

**The value.** `Access-Control-Allow-Credentials` carries one value and the CORS check compares it as bytes: `true` returns success and every other value falls through to the algorithm's failure. So `TRUE`, `false`, `1` or anything else is a header that is present and shares nothing, and is reported as that. The comparison here used to be case-insensitive, which told an operator that `TRUE` had enabled credentialed sharing.

**The pairing.** A value of `true` must **not** accompany an `Access-Control-Allow-Origin` of `*`: the CORS check only succeeds on the wildcard for a request whose credentials mode is not "include", and a credentialed request must match the byte-serialized origin instead, which `*` never is. A server sending both is advertising a sharing it will never get.

The origin header is only scanned for a `*` here; what its value may be is `access_control_allow_origin_valid`'s finding.

## Specifications

- [MDN Access-Control-Allow-Credentials](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Credentials): Access-Control-Allow-Credentials
- [MDN Access-Control-Allow-Origin](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Origin): Access-Control-Allow-Origin
- [Fetch §4.10](https://fetch.spec.whatwg.org/#concept-cors-check): Fetch CORS check — `*` succeeds only for non-credentialed requests, so `*` paired with `Access-Control-Allow-Credentials: true` can never authorize a credentialed request (the two cited steps)

## Configuration

```toml
[rules.access_control_allow_credentials_when_origin]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://example.com
Access-Control-Allow-Credentials: true
```

### ✅ Good (no credentials)

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
```

### ❌ Bad (wildcard with credentials)

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```
