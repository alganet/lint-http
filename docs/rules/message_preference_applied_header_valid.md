<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Preference-Applied header validity

## Description

Validate that the `Preference-Applied` response header follows the ABNF in RFC 7240 §3 and that each applied preference corresponds to a preference present in the request's `Prefer` header. Parameters (semicolon-separated) are not allowed in `Preference-Applied` members.

## Specifications

- [RFC 7240 §3](https://www.rfc-editor.org/rfc/rfc7240.html#section-3) — `Preference-Applied` header field and syntax

## Configuration

Minimal example to enable the rule:

```toml
[rules.message_preference_applied_header_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
GET / HTTP/1.1
Prefer: return=representation

HTTP/1.1 200 OK
Preference-Applied: return=representation
```

### ✅ Good (server indicates token applied without value)

```http
GET / HTTP/1.1
Prefer: return=representation

HTTP/1.1 200 OK
Preference-Applied: return
```

### ❌ Bad (applied token not present in request)

```http
HTTP/1.1 200 OK
Preference-Applied: respond-async
```

### ❌ Bad (parameters are not allowed in Preference-Applied)

```http
HTTP/1.1 200 OK
Preference-Applied: return; foo=bar
```
