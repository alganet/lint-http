<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Content Encoding Registered

## Description

Validate `Content-Encoding` and `Accept-Encoding` header values: each content-coding must be a valid `token` and must appear in the `allowed` array you configure.

**It does not consult the IANA registry**, despite the rule's name. RFC 9110 says content codings *ought to* be registered, which is the motivation, but a coding is recognised here exactly when your `allowed` array covers it. Comparisons are case-insensitive.

The two headers do not share a vocabulary. `Accept-Encoding` additionally admits `*` (matching any coding not listed) and `identity` (meaning no encoding); both are preference vocabulary and neither is a content-coding, so in `Content-Encoding` they are flagged — `identity` explicitly so, since RFC 9110 §8.4 reserves it for its Accept-Encoding role and says it SHOULD NOT be included.

**Both fields are read as octets and over the whole field section.** A coding name holding an octet outside visible US-ASCII is not a `token` and is reported as that; the reader this replaces refused such a value outright, so the field went unread and unreported. It also took only the first field line, where `#content-coding` makes every line of a section one list.

**An empty `Content-Encoding` list element is reported, and a field line holding no element at all is not.** §5.6.1.2 expands `#element` with every position bracketed and tells a recipient to ignore what that admits; §5.6.1.1 expands the same construct for a sender with nothing bracketed and forbids generating one. So `gzip,,br` is a comma the sender may not write, while a bare `Content-Encoding:` is the zero-element list the construct generates. That check is per field line rather than over the joined value, because a line holding no element becomes an empty element only in the join, which is a claim about the join. `Accept-Encoding`'s stray comma is `accept_encoding_parameter_valid`'s finding, not this rule's.

## Violations

- [content_coding_identity_forbidden](../violations/content_coding_identity_forbidden.md) — The identity coding is named where a coding belongs
- [content_coding_unregistered](../violations/content_coding_unregistered.md) — Content coding is not one the deployment recognises
- [content_coding_wildcard_forbidden](../violations/content_coding_wildcard_forbidden.md) — The Accept-Encoding wildcard is written where a coding belongs
- [list_member_empty](../violations/list_member_empty.md) — List holds an empty element
- [token_character_forbidden](../violations/token_character_forbidden.md) — Token holds a character outside tchar
- [token_whitespace_or_control_forbidden](../violations/token_whitespace_or_control_forbidden.md) — Token holds whitespace or a control character

## Specifications

- [RFC 9110 §8.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.4): `Content-Encoding = #content-coding`, and the reservation of `identity` for Accept-Encoding — the reason it is flagged here
- [RFC 9110 §8.4.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.4.1): `content-coding = token`, case-insensitive, and the "ought to be registered" guidance that motivates the rule without being what it checks
- [RFC 9110 §12.5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.3): The wider Accept-Encoding grammar (`codings = content-coding / "identity" / "*"`), which is why the two headers are checked against different vocabularies
- [IANA HTTP Parameters](https://www.iana.org/assignments/http-parameters/http-parameters.xhtml#content-coding): The registry this rule is named after but does not read; the configured `allowed` array stands in for it
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): Tokens — `token = 1*tchar`, and the fifteen punctuation marks besides the digits and letters that `tchar` admits
- [RFC 9110 §5.6.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1): The list construct — `1#element => element *( OWS "," OWS element )`, and the sender's MUST NOT against an empty element

## Configuration

```toml
[rules.content_encoding_registered]
enabled = true
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
