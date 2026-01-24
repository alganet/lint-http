<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Timing-Allow-Origin Header Validity

## Description

Validate the `Timing-Allow-Origin` response header values. The header's value
must be `*` (wildcard), `null` (case-insensitive), or one or more serialized
origins (`scheme://host[:port]`). Multiple header fields are allowed and their
values are combined using HTTP list semantics. This rule detects header values
that cannot be decoded as visible US-ASCII, an entirely empty header value, and
invalid origin serializations.

## Specifications

- [Resource Timing §4.5.1 — `Timing-Allow-Origin` response header](https://www.w3.org/TR/resource-timing/#sec-timing-allow-origin)
- [RFC 6454 — Origin (serialized-origin form)](https://www.rfc-editor.org/rfc/rfc6454.html)

## Configuration

Enable the rule in `config.toml`:

```toml
[rules.message_timing_allow_origin_validity]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Timing-Allow-Origin: *
```

```http
HTTP/1.1 200 OK
Timing-Allow-Origin: https://example.com
```

```http
HTTP/1.1 200 OK
Timing-Allow-Origin: https://a, https://b
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Timing-Allow-Origin: https:///foo
```

```http
HTTP/1.1 200 OK
Timing-Allow-Origin: 
```

```http
HTTP/1.1 200 OK
Timing-Allow-Origin: 	
```