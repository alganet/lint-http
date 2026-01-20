<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Accept-Language Weight Validity

Validate `Accept-Language` quality (`q`) values and parameter forms in `Accept-Language` header members.

## Description

The `Accept-Language` header allows clients to specify languages and optional `q` weights that indicate preference. This rule validates that any parameters in `Accept-Language` members use valid `token` names and that `q` parameters are valid quality values in the range 0..1 with up to three decimal places.

## Specifications

- [RFC 9110 §7.2.5 — Accept-Language](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.2.5)
- [RFC 9110 §12.4.2 — Quality Values (q)](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.4.2)
- [RFC 9110 §5.6.6 — Parameters (token / quoted-string)](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.6)

The rule follows the same `q`/parameter validation semantics used across other headers in this project (0..1 with up to three decimals for `q`; parameter names must be `token`; parameter values must be `token` or `quoted-string`).

## Configuration

```toml
[rules.message_accept_language_weight_validity]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
GET / HTTP/1.1
Host: example.com
Accept-Language: en-US, fr;q=0.8
```

```http
GET / HTTP/1.1
Host: example.com
Accept-Language: *;q=0.5, en;q=0.7
```

```http
GET / HTTP/1.1
Host: example.com
Accept-Language: en;foo="a\"b"
```

### ❌ Bad

```http
GET / HTTP/1.1
Host: example.com
Accept-Language: en;q=1.0000
```

```http
GET / HTTP/1.1
Host: example.com
Accept-Language: en;badparam=bad value
```

```http
GET / HTTP/1.1
Host: example.com
Accept-Language: en;q=
```
