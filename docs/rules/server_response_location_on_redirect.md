<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# server_response_location_on_redirect

## Description

Checks that responses where the semantics call for a `Location` header include one. In particular, a `201 (Created)` response and many redirection responses (300, 301, 302, 303, 307, 308) SHOULD include a `Location` header referring to the created or preferred target resource.

## Specifications

- [RFC 9110 §10.2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.2) — `Location = URI-reference` and semantics for `201` and `3xx` responses.
- [RFC 9110 §15.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4) — Redirection status codes and their `Location` semantics.

## Configuration

Minimal example to enable the rule in `config.toml`:

```toml
[rules.server_response_location_on_redirect]
enabled = true
severity = "warn"
```

## Examples

✅ Good

```
HTTP/1.1 301 Moved Permanently
Location: https://example.org/new
```

```
HTTP/1.1 201 Created
Location: /resource/123
```

❌ Bad

```
HTTP/1.1 301 Moved Permanently
# missing Location header
```

```
HTTP/1.1 201 Created
# missing Location header
```
