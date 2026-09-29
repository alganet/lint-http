<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Content-Type IANA Registered

## Description

Reports a `Content-Type` naming a media type that the IANA Media Types registry does not hold, in a request or in a response.

**The registry is the check.** RFC 9110 §8.3.1 says media types *ought to* be registered, and this crate carries a snapshot of the registry to ask. It used to ask a short list in its configuration instead, which reported every registered type the list left out — `application/pdf`, `text/markdown`, `multipart/mixed` — as unregistered.

**`allowed` adds to the registry.** A deployment that knowingly uses a type nobody registered, such as `application/x-protobuf`, names it there, and the rule stops reporting it. It never narrows: a registered type the deployment does not serve is not what this entry is about. Entries may be exact (`text/plain`), a type wildcard (`image/*`), `*/*`, or a structured syntax suffix (`+json`, matching `application/vnd.example+json` but not `application/json` or `text/notjson`). The wildcard and suffix forms are conveniences of this configuration, not media-type syntax. Comparisons are case-insensitive.

**The finding is a `warn`, and why it is not more.** Registration is asked of whoever defines a type, and two parties that agree on an unregistered one exchange it without harm. What the registry buys is that a third party can learn what the bytes are.

## Violations

- [media_type_unregistered](../violations/media_type_unregistered.md) — A media type is not in the IANA registry

## Specifications

- [RFC 9110 §8.3.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.1): Media Type: `media-type = type "/" subtype parameters`, both halves `token` and both case-insensitive, and the "ought to be registered with IANA" guidance — guidance rather than a requirement, and not something this crate verifies
- [RFC 6838 §4.2.8](https://www.rfc-editor.org/rfc/rfc6838.html#section-4.2.8): Structured syntax suffixes — a suffix is appended to a base subtype after a `+`, which is what a `+json` allowlist entry matches
- [IANA Media Types](https://www.iana.org/assignments/media-types/media-types.xhtml): The registry this rule reads, as the snapshot this crate carries; the configured `allowed` array adds to it

## Configuration

```toml
[rules.content_type_registered]
enabled = true
# The IANA Media Types registry is the check, and this crate carries a snapshot
# of it. `allowed` names what this deployment knowingly uses beyond it, and adds
# to the registry rather than replacing it. An entry may be exact
# (`application/x-protobuf`), a type wildcard (`image/*`), `*/*`, or a
# structured syntax suffix (`+json`); the last three are conveniences of this
# option, not media-type syntax.
allowed = []
```

## Examples

### ✅ Good

```http
Content-Type: text/plain
Content-Type: application/json; charset=utf-8
Content-Type: application/ld+json
Content-Type: image/png
```

### ✅ Good (registered, whatever a deployment lists)

```http
Content-Type: application/pdf
Content-Type: text/markdown; charset=utf-8
```

### ❌ Bad

```http
Content-Type: application/vnd.unknown
Content-Type: text/x-custom
```
