<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Content-Type IANA Registered

## Description

This rule checks that `Content-Type` media types (in both requests and responses) appear in an allowlist you configure. It helps flag unregistered or accidental vendor types that may cause interoperability problems.

**It does not consult the IANA registry**, despite the rule's name: there is no lookup, and a media type is "registered" as far as this rule is concerned exactly when your `allowed` array covers it. RFC 9110 says media types *ought to* be registered, which is the motivation for the rule, but the check itself is your policy.

Entries may be exact (`text/plain`), a type wildcard (`image/*`), `*/*`, or a structured syntax suffix (`+json`, matching `application/vnd.example+json` but not `application/json` or `text/notjson`). The wildcard and suffix forms are conveniences of this configuration, not media-type syntax. Comparisons are case-insensitive.

## Specifications

- [RFC 9110 §8.3.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.1): `media-type` syntax, the case-insensitivity of its tokens, and the "ought to be registered with IANA" guidance that motivates this rule — guidance, not a requirement, and not something this rule verifies
- [RFC 6838 §4.2.8](https://www.rfc-editor.org/rfc/rfc6838.html#section-4.2.8): Structured syntax suffixes — a suffix is appended to a base subtype after a `+`, which is what a `+json` allowlist entry matches
- [IANA Media Types](https://www.iana.org/assignments/media-types/media-types.xhtml): The registry this rule is named after but does not read; the configured `allowed` array stands in for it

## Configuration

```toml
[rules.message_content_type_iana_registered]
enabled = true
severity = "warn"
# The list has to carry the media types HTTP itself produces, or the rule
# reports the protocol working. `multipart/byteranges` is what a multi-range
# request gets back (RFC 9110 § 14.6) and `message/http` is what a TRACE
# response carries (RFC 9112 § 10.1) -- neither is a choice the origin made.
# `application/octet-stream` is the type RFC 9110 § 8.3 names for content whose
# type is unknown, so a default that rejects it rejects the specified fallback.
#
# The rest are the ordinary shapes of a request body, a non-JSON API, and the
# subresources a browser fetches for any page it renders. The stylesheet, script
# and font types are registered and are served by essentially every deployment
# with a web front end, so leaving them out reported conformant traffic on any
# corpus a browser produced -- the same defect as rejecting `message/http`, one
# step further out.
#
# A deployment is still expected to narrow this to what it actually serves.
allowed = [
  "text/plain",
  "text/html",
  "text/css",
  "text/javascript",
  "application/javascript",
  "application/json",
  "application/xml",
  "application/wasm",
  "application/octet-stream",
  "application/x-www-form-urlencoded",
  "multipart/byteranges",
  "multipart/form-data",
  "message/http",
  "font/woff",
  "font/woff2",
  "image/*",
  "+json",
]
```

## Examples

### ✅ Good

```http
Content-Type: text/plain
Content-Type: application/json; charset=utf-8
Content-Type: application/ld+json
Content-Type: image/png
```

### ❌ Bad

```http
Content-Type: application/vnd.unknown
Content-Type: text/x-custom
```
