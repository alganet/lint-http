<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Well-Known URI Format

## Description

Reads the request target's path component against RFC 8615's definition of a well-known URI: *"A well-known URI is a URI [RFC3986] whose path component begins with the characters "/.well-known/", provided that the scheme is explicitly defined to support well-known URIs."*

**Every finding here is advice, and the rule says so in each message.** RFC 8615 states five BCP 14 requirements and all five are addressed to an application minting or registering a name — it MUST register it, the name MUST conform to `segment-nz`, the name SHOULD be precise, an alternative port MUST be specified by the application, and a registration MAY carry additional path components. **None of them is a requirement on a request target.** The sentences a request can be measured against are definitions, so what this rule reports is that a path is not a well-known URI, never that sending it was forbidden: §1 names an origin's control over its own URI space as the thing this memo takes care not to usurp, and the paths below are ordinary resources of that origin.

**What is reported.**

- **A `.well-known` segment that is not the first one.** §3: *"Well-known URIs are rooted in the top of the path's hierarchy; they are not well-known by definition in other parts of the path."* — with the document's own counter-example, `/foo/.well-known/example`.
- **A path that is exactly `/.well-known`.** The prefix §1 reserves includes its trailing slash, so this is one character short of it.
- **An empty name after the prefix** (`/.well-known/`, and `/.well-known//name`). A registered name *"MUST conform to the "segment-nz" production"*, which is `1*pchar` — a cardinality floor an empty segment does not clear — and §3 adds that it defines no format or media type for the resource at the prefix itself.
- **A name holding a character `pchar` does not generate.** The same `segment-nz`, read for its alphabet.

**Only the first segment after the prefix is the name.** *"This means they cannot contain the "/" character."* is about the registered name, and the MAY beside it licenses *"the syntax of additional path components, query strings, and/or fragment identifiers to be appended to the well-known URI"* — so `/.well-known/est/simpleenroll` names `est` and is not a finding.

**The path is read as a path, not as a string.** It is walked as segments, so `/.well-knownfoo` — an ordinary path that happens to begin with the same characters — draws nothing. The percent-encoded `unreserved` octets are decoded first — RFC 3986 §2.4's exception says they can be decoded at any time, needing no component boundary established for them — and the dot segments are removed from the decoded path (§6.2.2.3), so `/a/../.well-known/x` and `/a/%2E%2E/.well-known/x` are the one path they both name, and `%2Ewell-known` and `.well-known` are the one segment §2.3 makes them. Nothing else is decoded, since decoding a delimiter would move the component boundaries (§2.4). Case is **not** normalized: §6.2.2.1 leaves path components case-sensitive, so `/.WELL-KNOWN/x` is a different path.

**The scheme proviso is the second half of the definition.** RFC 8615 updates the `http` and `https` schemes to support well-known URIs and no others; other schemes carry them *"only when those schemes' definitions explicitly allow it"*, which the "Well-Known URI Support" column of the URI Schemes registry tracks (§5.2). An origin-form target names no scheme and needs none, because an HTTP request's target URI is an `http` or an `https` one either way. An **absolute-form target naming any other scheme** — how a request to a forward proxy is written — draws nothing: which schemes have been added to that column since 2019 is an open registry this rule does not read, so the effect is a finding not made, never a finding made wrongly.

**What this rule declines, and why.**

- **Whether the name is registered.** The registry is Specification Required and §3.1 lets third parties register a widely deployed name, so an unregistered name is a name awaiting a registration, not a defect. No sentence makes requesting one wrong, and there is no list to check it against that would not go stale between releases.
- **The `SHOULD` for precise names.** *"Registered names for a specific application SHOULD be correspondingly precise; "squatting" on generic terms is not encouraged."* — a judgement about a name's meaning, made by the registry's experts.
- **The port.** *"Typically, applications will use the default port for the given scheme; if an alternative port is used, it MUST be explicitly specified by the application in question."* Deciding it means reading the registration that named the port, which no capture carries.
- **Whether a resource exists at the prefix.** §3's *"clients should not expect a resource to exist at that location"* is lowercase, and §2 makes the BCP 14 keywords apply *"when, and only when, they appear in all capitals"*.

**What other rules own.** A malformed percent-encoding anywhere in the request target, and any character outside the set a URI is composed from, are `client_request_uri_percent_encoding_valid`'s findings, asked of the whole target; the `pchar` check here is the same question at a narrower width, and within a path segment the only characters it adds are `[` and `]`. A fragment on the request target is `client_request_target_no_fragment`'s, and which of the four request-target forms may carry a path is `client_request_target_form_checks`'.

## Specifications

- [RFC 8615 §1](https://www.rfc-editor.org/rfc/rfc8615.html#section-1): Introduction — the prefix this memo reserves, trailing slash included; that other schemes carry well-known URIs only where their definitions allow it; and the origin's control over its own URI space
- [RFC 8615 §2](https://www.rfc-editor.org/rfc/rfc8615.html#section-2): Notational Conventions — the BCP 14 keywords apply when, and only when, they appear in all capitals, which is why §3's lowercase "should not expect a resource" is declined
- [RFC 8615 §3](https://www.rfc-editor.org/rfc/rfc8615.html#section-3): Well-Known URIs — the definition and its scheme proviso, the `segment-nz` MUST on a registered name, the MAY for additional path components, and the sentence saying a `.well-known` elsewhere in the path is not one
- [RFC 8615 §3.1](https://www.rfc-editor.org/rfc/rfc8615.html#section-3.1): Registering Well-Known URIs — the registry, and that a widely deployed name may be registered by a third party, which is why an unregistered name is not a finding
- [RFC 8615 §5.1](https://www.rfc-editor.org/rfc/rfc8615.html#section-5.1): The Well-Known URI Registry — Specification Required, on the advice of experts
- [RFC 8615 §5.2](https://www.rfc-editor.org/rfc/rfc8615.html#section-5.2): The URI Schemes Registry — the "Well-Known URI Support" column that tracks which schemes carry well-known URIs
- [RFC 3986 §3.3](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.3): Path — `segment-nz = 1*pchar`, what a `pchar` is, and where the path component ends
- [RFC 3986 §2.3](https://www.rfc-editor.org/rfc/rfc3986.html#section-2.3): Unreserved Characters — the production, and the equivalence that makes `%2Ewell-known` and `.well-known` the same segment
- [RFC 3986 §6.2.2.1](https://www.rfc-editor.org/rfc/rfc3986.html#section-6.2.2.1): Case Normalization — the components other than scheme and host are case-sensitive, so the prefix is matched as written
- [RFC 3986 §6.2.2.3](https://www.rfc-editor.org/rfc/rfc3986.html#section-6.2.2.3): Path Segment Normalization — dot segments are removed before the path's hierarchy is read, and *after* the `unreserved` octets are decoded, so an encoded `%2E%2E` is the dot segment it stands for
- [RFC 9112 §3.2](https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2): Request Target — the four forms, two of which carry no path component

## Configuration

```toml
[rules.message_well_known_uri_format]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good The URI §3 prints for a registered name 'example'

```http
GET /.well-known/example HTTP/1.1
Host: www.example.com
```

### ✅ Good Additional path components appended to the name, which §3's MAY licenses

```http
GET /.well-known/est/simpleenroll HTTP/1.1
Host: example.com
```

### ✅ Good An ordinary path that merely begins with the same characters

```http
GET /.well-knownfoo HTTP/1.1
Host: example.com
```

### ✅ Good Dot segments resolve to the reserved prefix

```http
GET /a/../.well-known/security.txt HTTP/1.1
Host: example.com
```

### ❌ Bad §3's own counter-example — not at the top of the path's hierarchy

```http
GET /foo/.well-known/example HTTP/1.1
Host: example.com
```

### ❌ Bad The reserved prefix without its trailing slash

```http
GET /.well-known HTTP/1.1
Host: example.com
```

### ❌ Bad No name after the prefix — `segment-nz` is `1*pchar`

```http
GET /.well-known/ HTTP/1.1
Host: example.com
```

### ❌ Bad A name holding a character `pchar` does not generate

```http
GET /.well-known/a[b] HTTP/1.1
Host: example.com
```
