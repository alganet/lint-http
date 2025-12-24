<!--
SPDX-FileCopyrightText: 2025 Alexandre Gomes Gaigalas <alganet@gmail.com>
SPDX-License-Identifier: ISC
-->

# server_last_modified_rfc1123_format

## Description

Verify that the `Last-Modified` header (when present) uses the IMF-fixdate format (a.k.a. RFC 1123 date) as required by HTTP date formatting rules.

## Specifications

- [RFC 9110 §7.7.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.7.1): Date and time formats — HTTP dates should be in IMF-fixdate format (e.g., `Wed, 21 Oct 2015 07:28:00 GMT`).

## Configuration

Minimal example to enable the rule in `config.toml`:

```toml
[rules.server_last_modified_rfc1123_format]
enabled = true
severity = "warn"
```

## Examples

✅ Good

```http
HTTP/1.1 200 OK
Last-Modified: Wed, 21 Oct 2015 07:28:00 GMT
Content-Type: text/plain

Hello
```

❌ Bad

```http
HTTP/1.1 200 OK
Last-Modified: 2015-10-21T07:28:00Z
Content-Type: text/plain

Hello
```
