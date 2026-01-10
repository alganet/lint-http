<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_content_encoding_iana_registered

## Description

Validate `Content-Encoding` and `Accept-Encoding` header values to ensure content-coding tokens are syntactically valid and are recognised (SHOULD be IANA-registered or explicitly allowed via configuration). The rule flags unrecognised content-coding tokens and invalid token characters.

## Specifications

- [RFC 9110 §5.3 — Content Coding](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3)
- [IANA Content Coding registry](https://www.iana.org/assignments/http-parameters/http-parameters.xhtml#content-coding)

## Configuration

This rule **requires** an `allowed` list (array of strings) that declares the content-codings considered acceptable. The project does not embed a default allow-list in code; include the canonical IANA Content Coding registry (or a subset you trust) in your configuration. See the IANA registry: https://www.iana.org/assignments/http-parameters/content-coding.csv

Example (canonical IANA list):

```toml
[rules.message_content_encoding_iana_registered]
enabled = true
severity = "warn"
allowed = ["aes128gcm", "br", "compress", "dcb", "dcz", "deflate", "exi", "gzip", "identity", "pack200-gzip", "x-compress", "x-gzip", "zstd"]
```

## Examples

✅ Good

```http
Content-Encoding: gzip
Content-Encoding: gzip, br
Accept-Encoding: gzip;q=0.8, br;q=1.0
Accept-Encoding: *
```

❌ Bad

```http
Content-Encoding: x-custom
Accept-Encoding: x-custom;q=0.5
Accept-Encoding: x!bad  # invalid token character '!'
```
