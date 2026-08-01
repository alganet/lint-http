<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Content Encoding Iana Registered

## Description

Validate `Content-Encoding` and `Accept-Encoding` header values: each content-coding must be a valid `token` and must appear in the `allowed` array you configure.

**It does not consult the IANA registry**, despite the rule's name. RFC 9110 says content codings *ought to* be registered, which is the motivation, but a coding is recognised here exactly when your `allowed` array covers it. Comparisons are case-insensitive.

The two headers do not share a vocabulary. `Accept-Encoding` additionally admits `*` (matching any coding not listed) and `identity` (meaning no encoding); both are preference vocabulary and neither is a content-coding, so in `Content-Encoding` they are flagged — `identity` explicitly so, since RFC 9110 §8.4 reserves it for its Accept-Encoding role and says it SHOULD NOT be included.

## Specifications

- [RFC 9110 §8.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.4): `Content-Encoding = #content-coding`, and the reservation of `identity` for Accept-Encoding — the reason it is flagged here
- [RFC 9110 §8.4.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.4.1): `content-coding = token`, case-insensitive, and the "ought to be registered" guidance that motivates the rule without being what it checks
- [RFC 9110 §12.5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.3): The wider Accept-Encoding grammar (`codings = content-coding / "identity" / "*"`), which is why the two headers are checked against different vocabularies
- [IANA HTTP Parameters](https://www.iana.org/assignments/http-parameters/http-parameters.xhtml#content-coding): The registry this rule is named after but does not read; the configured `allowed` array stands in for it

## Configuration

```toml
[rules.message_content_encoding_iana_registered]
enabled = true
severity = "warn"
allowed = ["aes128gcm", "br", "compress", "dcb", "dcz", "deflate", "exi", "gzip", "identity", "pack200-gzip", "x-compress", "x-gzip", "zstd"]
```

## Examples

### ✅ Good

```http
Content-Encoding: gzip
Content-Encoding: gzip, br
Accept-Encoding: gzip;q=0.8, br;q=1.0
Accept-Encoding: *
```

### ❌ Bad

```http
Content-Encoding: x-custom
Accept-Encoding: x-custom;q=0.5
Accept-Encoding: x!bad  # invalid token character '!'
```
