<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Content Location And Uri Consistency

## Description

Validate `Content-Location` header values. The value must be a well-formed URI reference (`absolute-URI / partial-URI`) with no whitespace, sound percent-encoding and a valid scheme where one is present, and — since neither alternative of the grammar is a comma-separated list — a message carries at most one `Content-Location` field line (RFC 9110 §5.3).

For 2xx responses the rule additionally compares the value against the request target, resolving a `partial-URI` against it first as RFC 9110 §8.7 requires ("after conversion to absolute form"), so a relative reference that names the target resource is not reported.

**A difference is not a protocol error.** RFC 9110 §8.7 attaches no requirement to a differing `Content-Location`: it means "the origin server claims that the URI is an identifier for a different resource", which is exactly what a negotiated variant, a 201 pointing at the created resource, or a POST report is supposed to say. The rule reports the difference as an advisory — `config_example.toml` ships it at `info` — because the claim "can only be trusted if both identifiers share the same resource owner, which cannot be programmatically determined via HTTP", so it is worth a human glance and nothing stronger. Raise the severity only if your deployment intends `Content-Location` to always echo the target.

## Specifications

- [RFC 9110 §8.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.7): Content-Location

## Configuration

```toml
[rules.message_content_location_and_uri_consistency]
enabled = true
severity = "info"
```

## Examples

### ✅ Good

```http
GET /foo HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Location: /foo
Content-Type: text/plain

Hello
```

### ✅ Good (absolute)

```http
GET /foo HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Location: http://example.com/foo
Content-Type: text/plain

Hello
```

### ✅ Good (relative reference resolving to the target)

```http
GET /dir/foo.html HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Location: foo.html
Content-Type: text/html

<p>Hello
```

### ❌ Bad (invalid percent-encoding)

```http
HTTP/1.1 200 OK
Content-Location: /bad%2G
```

### ❌ Bad (contains whitespace)

```http
HTTP/1.1 200 OK
Content-Location: /bad path
```

### ❌ Bad (two field lines — Content-Location is a singleton)

```http
HTTP/1.1 200 OK
Content-Location: /foo
Content-Location: /bar
```

### ❌ Bad (negotiated variant — reported as an advisory, not an error)

```http
GET /foo HTTP/1.1
Host: example.com
Accept-Language: en

HTTP/1.1 200 OK
Content-Location: /foo.en.html
Content-Type: text/html

<p>Hello
```
