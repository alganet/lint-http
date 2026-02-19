<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# HEAD response headers match GET

## Description

Ensure responses to `HEAD` mirror the header fields that would have been sent for a `GET` on the same resource. A `HEAD` response MUST omit the message body but SHOULD include the same representation metadata and header fields as the corresponding `GET` response. The rule flags cases where the observed `HEAD` response omits or adds header fields compared with a previously observed `GET` for the same request-target, with a small set of RFC-permitted exceptions (see Specifications).

## Specifications

- [RFC 9110 §9.3.2 — The HEAD method and header-field equivalence](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.2): "The server SHOULD send the same header fields in response to a HEAD request as it would have sent if the request method had been GET." (exceptions allowed for headers whose values are determined only while generating content.)
- [RFC 9110 §8.6 — Content-Length](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6): a server MAY send Content-Length in a `HEAD` response but if present its value MUST equal the decimal number of octets that would have been sent in the content of the corresponding `GET` response.

## Configuration

This rule **requires** a `headers` array listing the header field-names (case-insensitive) that must be consistent between a previously observed `GET` and a subsequent `HEAD`. There is **no default** — the array must be provided in your config.

```toml
[rules.semantic_head_response_headers_match_get]
enabled = true
severity = "warn"
headers = ["etag", "content-type", "content-length"]
```

## Examples

### ✅ Good

```http
# Previous GET
GET /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
ETag: "v2"
Content-Type: text/plain
Content-Length: 42

...body...

# Later HEAD for same resource (headers match)
HEAD /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
ETag: "v2"
Content-Type: text/plain
Content-Length: 42
```

### ❌ Bad

```http
# Previous GET
GET /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
ETag: "v2"
Content-Type: text/plain

...body...

# Later HEAD for same resource (missing ETag)
HEAD /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Type: text/plain
```

```http
# Previous GET
GET /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 100

...body...

# Later HEAD for same resource (Content-Length differs)
HEAD /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 50
```
