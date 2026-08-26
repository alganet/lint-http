<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Alt-Svc H3 Advertisement Valid

## Description

Reads the `Alt-Svc` response header field for the entries that advertise HTTP/3, and asks two things of each: that it names the shipped protocol, and that the freshness lifetime it carries is one.

**The protocol identifier.** RFC 9114 §3.1.1: *"An HTTP origin can advertise the availability of an equivalent HTTP/3 endpoint via the Alt-Svc HTTP response header field or the HTTP/2 ALTSVC frame ([ALTSVC]) using the "h3" ALPN token."* A draft-era token — `h3-29`, `h3-Q050`, `h3-27` — is a different ALPN protocol name, so a client that speaks HTTP/3 and not that draft finds nothing it can use at the alternative.

**The `ma` parameter.** RFC 7838 §3.1 gives it a `delta-seconds` value, and `delta-seconds` is `1*DIGIT` (RFC 9111 §1.2.2) — **the production, not an integer type**. A leading `+` is not part of it, so `ma=+5` is reported even though every standard-library parser reads it as 5; conversely a run of digits longer than 64 bits is a conforming value that RFC 9111 §1.2.2 tells a cache to clamp rather than reject, so it is measured against this rule's ceiling instead of being called malformed. `ma=0` is fresh for zero seconds — the advertisement is stale as it arrives — and is reported as the likely misconfiguration it is.

**The ceiling is a heuristic and is the one thing here with no sentence behind it.** RFC 7838 places no upper bound on `ma`. One year (31 536 000 seconds) is this linter's guess at where a value stops being a policy and starts being a typo.

**The parameter name is compared case-sensitively, and the protocol identifier is not.** RFC 7838 prints `parameter = token "=" ( token / quoted-string )` and states no case-insensitivity for the name; RFC 9110 §5.6.6's *"Parameter names are case-insensitive"* governs the `parameters` production, which this field does not import. So `MA=0` is a parameter name a client is required to ignore (*"Unknown parameters MUST be ignored."*), and reporting it as invalidating an advertisement would describe something that does not happen. The **protocol identifier** is folded to lowercase, deliberately and against §3's *"simple string comparison"*: the fold only ever widens what this rule reports, so `H3-29` is still named as a draft token and `H3=…; ma=0` is still measured.

**What this rule leaves to its two siblings.** Everything about the field's shape is `alt_svc_header_syntax`'s, on every protocol rather than on `h3` alone: an empty list element, an `alternative` with no `=`, an empty `protocol-id`, a percent-encoding this field's one-spelling constraints forbid, a `parameter` with no value or a value that is neither a `token` nor a well-formed `quoted-string`, and an unterminated DQUOTE — which this rule treats as making the whole value unreadable rather than guessing at where its members end. Whether the ALPN name is registered is `alt_svc_protocol_registered`'s.

The field lines are joined before they are read (RFC 9110 §5.3), because `1#alt-value` is the list that licenses the join, and the value is read one `char` per octet so that an `obs-text` octet is measured rather than hiding the line it is written on.

## Specifications

- [RFC 9114 §3.1.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-3.1.1): HTTP Alternative Services — advertising HTTP/3 via Alt-Svc using the "h3" ALPN token
- [RFC 7838 §3](https://www.rfc-editor.org/rfc/rfc7838.html#section-3): Alt-Svc — the field's grammar, the `parameter` production, and the requirement that a recipient ignore a parameter name it does not know
- [RFC 7838 §3.1](https://www.rfc-editor.org/rfc/rfc7838.html#section-3.1): Caching Alt-Svc Header Field Values — what the `ma` parameter's delta-seconds value means
- [RFC 9111 §1.2.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-1.2.2): delta-seconds — the `1*DIGIT` production `ma` carries, and what a cache does with a value too large to represent

## Configuration

```toml
[rules.alt_svc_h3_advertisement_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good The shipped ALPN token, with a freshness lifetime

```http
Alt-Svc: h3=":443"; ma=2592000
```

### ✅ Good No `ma` at all: the parameter is optional

```http
Alt-Svc: h3=":443"
```

### ✅ Good An `h3` entry beside another protocol's

```http
Alt-Svc: h2=":443", h3=":443"; ma=3600
```

### ✅ Good A parameter name this document does not define is ignored, not folded

```http
Alt-Svc: h3=":443"; MA=0
```

### ❌ Bad A draft protocol identifier

```http
Alt-Svc: h3-29=":443"
```

### ❌ Bad Fresh for zero seconds: stale as it arrives

```http
Alt-Svc: h3=":443"; ma=0
```

### ❌ Bad Beyond the one-year ceiling this linter guesses at

```http
Alt-Svc: h3=":443"; ma=99999999
```

### ❌ Bad No `delta-seconds`: `1*DIGIT` writes no sign

```http
Alt-Svc: h3=":443"; ma=+5
```
