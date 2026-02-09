<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Client Prefer Header and Preference-Applied Presence

## Description

When a client sends a `Prefer` request header, servers MAY include a `Preference-Applied` response header to indicate which preferences were applied. This rule warns when a request included `Prefer` but the response did not include `Preference-Applied`, which makes it harder for clients to know which preferences the server applied. This is a best-practice suggestion; servers are not strictly required to include `Preference-Applied`.

## Specifications

- [RFC 7240 §3](https://www.rfc-editor.org/rfc/rfc7240.html#section-3) — `Preference-Applied` header and ABNF

## Configuration

Minimal example to enable the rule:

```toml
[rules.client_prefer_header_and_preference_applied]
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

### ❌ Bad (response omits Preference-Applied)

```http
GET / HTTP/1.1
Prefer: return=representation

HTTP/1.1 200 OK
```
