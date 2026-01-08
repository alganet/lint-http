<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Client Request Target Form Checks

## Description

Validate the form of the request-target according to RFC 9112 §2.7. This rule enforces that:

- `CONNECT` requests MUST use the authority-form (host[:port]).
- The asterisk form (`*`) is only valid for `OPTIONS` requests.
- Authority-form request-targets MUST NOT be used with methods other than `CONNECT`.

These checks help ensure request-targets are semantically correct and avoid ambiguous targets that can lead to proxy/origin misinterpretation.

## Specifications

- [RFC 9112 §2.7](https://www.rfc-editor.org/rfc/rfc9112.html#section-2.7) — Request Target Forms: origin-form, absolute-form, authority-form, asterisk-form.

## Configuration

```toml
[rules.client_request_target_form_checks]
enabled = true
severity = "error"
```

## Examples

### ✅ Good Request
```http
CONNECT example.com:443
OPTIONS *
GET /resource
GET http://example.com/resource
```

### ❌ Bad Request
```http
CONNECT /not-authority
GET example.com:443
POST *
```