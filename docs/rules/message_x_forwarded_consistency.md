<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message X-Forwarded Consistency

## Description

Validates the legacy `X-Forwarded-For`, `X-Forwarded-By`, `X-Forwarded-Proto` and `X-Forwarded-Host` request fields.

**No specification defines these fields.** RFC 7239 §1 names the first three and calls them non-standard; §7.4 says what a proxy should convert them into, and that conversion is the only route by which any sentence reaches them. This rule follows it:

- an `X-Forwarded-For` or `X-Forwarded-By` member becomes a `for=` / `by=` value, so it is measured against RFC 7239 §6's node identifier — an IPv4 address, an IPv6 address, `unknown`, or an obfuscated identifier beginning with an underscore, each optionally followed by `:` and a port of one to five digits or an obfuscated port. §7.4 records that an IPv6 address is written here **without** the quotes and square brackets it wears inside `Forwarded`, so both spellings are accepted and neither is reported;
- an `X-Forwarded-Proto` member becomes a `proto=` value, which RFC 7239 §5.4 requires to be a URI scheme name (RFC 3986 §3.1). `http` and `https` are what that section calls *typical*, not what it permits, so `wss` and any other well-formed scheme name pass;
- an `X-Forwarded-Host` member is measured against the `Host` field ABNF (RFC 9110 §7.2), whose port is `*DIGIT` — no lower bound, no upper bound, and no digits at all is a port.

All four field names are read across every field line of the request, and each line is read octet by octet, so a value outside US-ASCII is reported as a character the production does not generate rather than skipped.

**What this rule does not check.** The mapping of `X-Forwarded-Host` onto `host=` is the only one of the four that no sentence states — §1 does not name that field, and it is reached by §7.4's `X-Forwarded-*` wildcard together with §5.3's description of what a `host` parameter carries. A scheme name is not checked against the IANA URI scheme registry, which is open. An empty member (`a,,b`) is skipped rather than reported: RFC 9110 §5.6.1.1's prohibition is written about fields whose definition uses the list extension, and these fields have no definition. These are request fields, and a response carrying one is not examined.

Despite its name, this rule checks each field on its own and cross-checks nothing: a message carrying both `Forwarded` and `X-Forwarded-For`, or an `X-Forwarded-Host` disagreeing with `Host`, is not reported. §7.4 encourages the conversion between the two families but states no relationship a receiver could measure, and it is explicit that where several `X-Forwarded-*` fields are present the order they were added in cannot be recovered.

## Specifications

- [RFC 7239 §7.4](https://www.rfc-editor.org/rfc/rfc7239.html#section-7.4): Transition: what each `X-Forwarded-*` field converts into, and the one difference in how an IPv6 address is written there. The only sentences in any specification that reach these fields.
- [RFC 7239 §1](https://www.rfc-editor.org/rfc/rfc7239.html#section-1): Names `X-Forwarded-For`, `X-Forwarded-By` and `X-Forwarded-Proto` as non-standard header fields
- [RFC 7239 §6](https://www.rfc-editor.org/rfc/rfc7239.html#section-6): `node` — the identifier an `X-Forwarded-For` / `X-Forwarded-By` member becomes once §7.4's conversion prepends `for=` / `by=`
- [RFC 7239 §5.4](https://www.rfc-editor.org/rfc/rfc7239.html#section-5.4): `proto` is a URI scheme name; `http` and `https` are called typical, not exhaustive
- [RFC 7239 §5.3](https://www.rfc-editor.org/rfc/rfc7239.html#section-5.3): `host` conforms to the `Host` field ABNF. That `X-Forwarded-Host` is the field this parameter carries is a reading of §7.4's `X-Forwarded-*` wildcard, not a sentence.
- [RFC 9110 §7.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.2): `Host = uri-host [ ":" port ]`, the production an `X-Forwarded-Host` member is measured against

## Configuration

```toml
[rules.message_x_forwarded_consistency]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good The chain §7.4 prints, with the host and protocol the proxy saw

```http
GET / HTTP/1.1
Host: internal.example
X-Forwarded-For: 192.0.2.43, 2001:db8:cafe::17
X-Forwarded-Proto: https
X-Forwarded-Host: example.com:443
```

### ✅ Good An obfuscated identifier and a node port are node identifiers, and `wss` is a URI scheme name

```http
GET / HTTP/1.1
Host: internal.example
X-Forwarded-For: _gazonk, 192.0.2.43:47011, unknown
X-Forwarded-By: _SEVKISEK
X-Forwarded-Proto: wss
```

### ✅ Good `port = *DIGIT` has no range in it, and no digits is a port

```http
GET / HTTP/1.1
Host: internal.example
X-Forwarded-Host: example.com:99999
```

### ❌ Bad Neither an address, nor `unknown`, nor underscore-led: nothing in §6 generates it

```http
GET / HTTP/1.1
Host: internal.example
X-Forwarded-For: not-an-ip
```

### ❌ Bad `@` is the userinfo delimiter and appears in no `uri-host`

```http
GET / HTTP/1.1
Host: internal.example
X-Forwarded-Host: user@host
```

### ❌ Bad A scheme name begins with a letter

```http
GET / HTTP/1.1
Host: internal.example
X-Forwarded-Proto: 2https
```
