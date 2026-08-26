<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Forwarded Header Valid

## Description

Validates `Forwarded` (RFC 7239 §4) against the grammar that defines it: the field is a list of elements, each a semicolon-separated sublist of `name=value` pairs whose names are tokens and whose values are tokens or quoted-strings, with no whitespace inside an element and no parameter named twice in one element.

The four registered parameters are checked against the sentences that define them. `for` and `by` must be a node identifier (RFC 7239 §6): an IPv4 address, a bracketed IPv6 address, `unknown`, or an obfuscated identifier — which **must begin with an underscore** and hold only letters, digits, `.`, `_` and `-` — each optionally followed by `:` and a port of one to five digits or an obfuscated port. An IPv6 address, and any node identifier carrying a port, must be written as a quoted-string, since `:` and `[]` are not token characters. `host` must conform to the `Host` field ABNF (RFC 9110 §7.2) and `proto` to a URI scheme name (RFC 3986 §3.1).

A `Forwarded` field in a **response** is reported: RFC 7239 §4 restricts the field to requests, and §8.2 explains that copying it into a response reveals the whole proxy chain to the client.

What this rule does not check: an extension parameter's name against the IANA "HTTP Forwarded Parameters" registry, or a `proto` value against the URI scheme registry — both registries are open and live elsewhere. A `Forwarded` field in a trailer section is reported by the trailer-fields rule, not here. The IPv6 recommendation of RFC 7239 §6.1 (RFC 5952 form: lowercase, zeroes compressed) is a SHOULD, and a value that parses but is written differently is reported as one.

## Specifications

- [RFC 7239 §4](https://www.rfc-editor.org/rfc/rfc7239.html#section-4): The field's grammar, the case-insensitivity of parameter names, the MUST NOT on naming a parameter twice in one element, and the sentence restricting the field to requests
- [RFC 7239 §6](https://www.rfc-editor.org/rfc/rfc7239.html#section-6): `node`, `nodename`, `node-port`: the obfuscated forms MUST begin with an underscore, a numeric port is one to five digits, and an address with a port MUST be quoted. §6.1's SHOULD asks for the RFC 5952 textual form
- [RFC 7239 §5](https://www.rfc-editor.org/rfc/rfc7239.html#section-5): The four registered parameters. `host` MUST conform to the Host ABNF and `proto` to a URI scheme name; extension parameters SHOULD be registered, in a registry this rule does not hold
- [RFC 7239 §8.2](https://www.rfc-editor.org/rfc/rfc7239.html#section-8.2): Why a response must not carry the field: it reveals the whole proxy chain to the client
- [RFC 9110 §7.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.2): `Host = uri-host [ ":" port ]`, which §5.3 makes the syntax of a `host` parameter
- [RFC 3986 §3.1](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.1): `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`, which §5.4 makes the syntax of a `proto` parameter

## Configuration

```toml
[rules.forwarded_header_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Forwarded: for=192.0.2.43;proto=https;by=203.0.113.5

Forwarded: for="[2001:db8::1]";host=example.com

Forwarded: for="192.0.2.43:47011", for=_gazonk

Forwarded: for=unknown;by=_SEVKISEK
```

### ❌ Bad

```http
Forwarded: for=999.999.999.999
# not an IPv4 address, and not a node identifier of any other kind

Forwarded: for=x-foo
# an obfuscated identifier must begin with an underscore

Forwarded: for=192.0.2.43:4711
# a node identifier with a port must be quoted: ':' is not a token character

Forwarded: for="192.0.2.43:123456"
# a numeric node-port is one to five digits

Forwarded: for=192.0.2.43;for=198.51.100.17
# a parameter may be named only once per element

Forwarded: proto=ht_tp
# a URI scheme name holds no underscore
```
