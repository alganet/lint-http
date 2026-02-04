<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# server_redirect_status_and_location_validity

## Description

Responses that indicate a resource has moved or been created (3xx redirections and 201 Created) commonly use the `Location` header to point to the target resource. A `Location` header appearing on responses that are not redirects or creations may indicate a misconfiguration or misuse; this rule flags `Location` header presence on non-redirect responses.

## Specifications

- [RFC 9110 §10.2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.2) — `Location = URI-reference` and semantics for redirection responses (3xx).
- [RFC 9110 §15.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4) — `201 Created` responses SHOULD include a `Location` header when a new resource is created.

## Configuration

This rule has no custom configuration; enable it in your `config.toml` with `enabled` and `severity`:

```toml
[rules.server_redirect_status_and_location_validity]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Content-Type: text/plain

Hello
```

### ✅ Good (redirect)

```http
HTTP/1.1 302 Found
Location: /new
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Location: /unexpected
```

