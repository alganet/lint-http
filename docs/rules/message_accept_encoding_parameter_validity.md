<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_accept_encoding_parameter_validity

Validate `Accept-Encoding` header parameters (quality values and parameter forms) follow RFC rules. In particular, this rule ensures `q` parameters are valid qvalues (0..1 with up to three decimals) and that parameter names and values follow `token` / `quoted-string` syntax.

## Description

`Accept-Encoding` members may include parameters such as `q` weights. This rule validates each member's parameters:

- Parameter names must be `token` characters.
- Parameter values must be a `token` or a `quoted-string`.
- The special `q` parameter must be a valid qvalue (for example: `0`, `0.5`, `1.0`, `0.123`).

Invalid parameter forms or `q` values are flagged.

## Specifications

- [RFC 9110 §12.5.3 — Accept-Encoding](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.3)
- [RFC 9110 §12.4.2 — Quality Values (q)](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.4.2)
- [RFC 9110 §5.6.6 — Parameters (token / quoted-string)](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.6)

## Configuration

Minimal example enabling the rule:

```toml
[rules.message_accept_encoding_parameter_validity]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
GET / HTTP/1.1
Host: example.com
Accept-Encoding: gzip;q=0.8
```

```http
GET / HTTP/1.1
Host: example.com
Accept-Encoding: br;q=1.0
```

```http
GET / HTTP/1.1
Host: example.com
Accept-Encoding: gzip
```

### ✅ Good (wildcard with q)

```http
GET / HTTP/1.1
Host: example.com
Accept-Encoding: *;q=0.5, gzip;q=0.8
```

### ❌ Bad (invalid q precision)

```http
GET / HTTP/1.1
Host: example.com
Accept-Encoding: gzip;q=1.0000
```

### ❌ Bad (invalid coding token)

```http
GET / HTTP/1.1
Host: example.com
Accept-Encoding: gzip@;q=0.5
```

### ❌ Bad (missing q value)

```http
GET / HTTP/1.1
Host: example.com
Accept-Encoding: gzip;q=
```
