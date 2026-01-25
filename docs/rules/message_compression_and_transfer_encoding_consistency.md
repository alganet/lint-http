<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_compression_and_transfer_encoding_consistency

## Description

Responses that use representation compression (e.g., `Content-Encoding: gzip`) should not duplicate the same compression coding in `Transfer-Encoding`. `Content-Encoding` signals end-to-end transformations applied to the representation by the origin, while `Transfer-Encoding` describes hop-by-hop transport codings. The rule flags cases where the same compression coding appears in both headers which is likely unintended and confusing.

## Specifications

- [RFC 9110 §5.3 — Content Coding](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3)
- [RFC 9112 §6.1 — Transfer Codings and `Transfer-Encoding`](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.1)

## Configuration

TOML snippet to enable the rule (disabled by default):

```toml
[rules.message_compression_and_transfer_encoding_consistency]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Content-Encoding: gzip
Transfer-Encoding: chunked

<compressed-body-chunked>
```

### ✅ Good (transfer-level gzip without Content-Encoding)

```http
HTTP/1.1 200 OK
Transfer-Encoding: gzip, chunked

<gzip-then-chunked-bytes>
```

### ❌ Bad (duplicate compression codings)

```http
HTTP/1.1 200 OK
Content-Encoding: gzip
Transfer-Encoding: gzip, chunked

<body>
```
