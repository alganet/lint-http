<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Alt-Svc Protocol IANA-Registered

## Description

Read the `protocol-id` of each `Alt-Svc` alternative as the ALPN protocol name it stands for, and ask whether that name is one this deployment offers.

**A `protocol-id` is not the name; it is an escaping of it.** RFC 7838 §3 writes `protocol-id = token ; percent-encoded ALPN protocol name` and says *"ALPN protocol names are octet sequences with no additional constraints on format"*, so every triplet is decoded before the comparison — delimiters included, because there are no components inside a name for a decoded delimiter to move. This matters for more registered names than it looks: `/` is not a `tchar`, so `http/1.1`, `acme-tls/1`, `ntske/1`, `sip/2` and `radius/1.1` all appear on the wire percent-encoded (`http%2F1.1`), and a list written from the registry would match none of them otherwise.

**The comparison is byte-exact.** RFC 7301 §3.1 says protocols are *"named by IANA-registered, opaque, non-empty byte strings"* and §6's registration template asks for *"the precise set of octet values that identifies the protocol"*, so `H2` is not `h2`. Neither side of the comparison is case-folded, and the registry itself carries a mixed-case entry.

**The `allowed` list is required and stands in for the registry.** Nothing here fetches <https://www.iana.org/assignments/tls-extensiontype-values>; RFC 7301 §6 hands the *"TLS Application-Layer Protocol Negotiation (ALPN) Protocol IDs"* registry (renamed by RFC 8447 §3) to a designated expert under Expert Review, so it gains entries between releases and a list compiled in here would answer for the day it was written. The list is written as ALPN protocol **names**, the octets IANA registers, and not as the escaped `protocol-id`s. What the finding rests on is what happens next: RFC 7301 §3.2 has a server with no protocol in common send a fatal `no_application_protocol` alert, and RFC 7838 §2.4 requires a client whose alternative does not negotiate the expected protocol to treat that connection as failed.

**One finding needs no configuration.** A `ProtocolName` is `opaque ProtocolName<1..2^8-1>`, so a name longer than 255 octets is one no ClientHello or ServerHello can carry, whatever any list says.

**What this rule declines, and to whom.** Everything that is the field's grammar rather than its registry goes to `alt_svc_header_syntax`, which reads the same field under the same scope with no gate this rule lacks: an unterminated `quoted-string`, an empty list element, an alternative with no `=`, an empty `protocol-id`, a character no `tchar` admits, a malformed percent triplet, and whitespace beside the `=`. So are the three spelling MUSTs on a well-formed triplet — a lowercase hex digit, an encoded `tchar`, an unencoded `%` — which that rule reports with the reason `x%3dy` and `x%3Dy` are two protocols to a recipient. Here a well-formed triplet is simply decoded, so `%68%32` is read as `h2` and reported once rather than twice. The `clear` keyword nominates no service and is skipped, matched case-sensitively because `%s"clear"` is. RFC 7838 §2.1's *"Clients MUST have reasonable assurances that the alternative service is under control of and valid for the whole origin"* — with the §2.1 example that `h2c` cannot provide them — is addressed to clients and is not reported against the server that advertised it. Draft HTTP/3 tokens are `alt_svc_h3_advertisement_valid`'s.

## Specifications

- [RFC 7838 §2](https://www.rfc-editor.org/rfc/rfc7838.html#section-2): Alternative Services Concepts: an alternative service is identified by an ALPN protocol name as per RFC 7301, a host and a port; §2.4 requires a client to treat a connection that does not negotiate the expected protocol as failed
- [RFC 7838 §3](https://www.rfc-editor.org/rfc/rfc7838.html#section-3): The Alt-Svc HTTP Header Field: `protocol-id = token ; percent-encoded ALPN protocol name`, the escaping table that is its round trip, and the `clear` keyword
- [RFC 7301 §3.1](https://www.rfc-editor.org/rfc/rfc7301.html#section-3.1): The Application-Layer Protocol Negotiation Extension: protocol names are IANA-registered opaque byte strings, carried in a `ProtocolName` vector of at most 255 octets; §3.2 is the fatal alert a server sends when nothing is in common
- [RFC 7301 §6](https://www.rfc-editor.org/rfc/rfc7301.html#section-6): IANA Considerations: the ALPN Protocol IDs registry, its Identification Sequence column, and its Expert Review policy — the reason the allowed list is configuration rather than a table compiled in here
- [RFC 8447 §3](https://www.rfc-editor.org/rfc/rfc8447.html#section-3): Adding "TLS" to Registry Names: the registry RFC 7301 §6 created is now "TLS Application-Layer Protocol Negotiation (ALPN) Protocol IDs"
- [IANA TLS ALPN Protocol IDs](https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#alpn-protocol-ids): TLS Application-Layer Protocol Negotiation (ALPN) Protocol IDs: the registry an operator writes the allowed list from — nothing in this rule reads it
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): Tokens: `token = 1*tchar`, the production a `protocol-id` is, and §5.3's rule for combining a field spread over several lines
- [RFC 3986 §2.1](https://www.rfc-editor.org/rfc/rfc3986.html#section-2.1): Percent-Encoding: `pct-encoded = "%" HEXDIG HEXDIG`, the triplet decoded back into an octet of the name

## Configuration

```toml
[rules.alt_svc_protocol_registered]
enabled = true
severity = "warn"
# ALPN protocol names — the octets IANA registers in the "TLS Application-Layer
# Protocol Negotiation (ALPN) Protocol IDs" registry — and not the escaped
# `protocol-id`s they are written as. `http/1.1` is listed here as itself and
# appears on the wire as `http%2F1.1`, because `/` is in no `token`. The
# comparison is byte-exact: an ALPN protocol name is identified by its precise
# octets, so `H2` is not `h2`.
#
# The registry is Expert Review and gains entries between releases, so this is
# the narrower and more useful list: the alternatives this deployment actually
# serves. Everything else is reported, registered or not.
#
# `h3-29` is listed because the draft-29 identifier is still advertised
# alongside `h3` by large operators, and this rule is not the one that has an
# opinion about that: naming a draft identifier where the final one exists
# belongs to `alt_svc_h3_advertisement_valid`, which reports it with the
# advice to use `h3`. Leaving `h3-29` out here made both rules report the same
# token on the same response, saying two different things about it.
allowed = ["h2", "h3", "h3-29", "h2c", "http/1.1"]
```

## Examples

### ✅ Good

```http
Alt-Svc: h2=":443"; ma=2592000
Alt-Svc: h3="example.com:8443"
Alt-Svc: http%2F1.1="old.example.com:443"  # the ALPN name is http/1.1
Alt-Svc: clear
```

### ❌ Bad

```http
Alt-Svc: xproto=":443"                    # names no ALPN protocol this deployment offers
Alt-Svc: H2="example.com:443"             # an ALPN protocol name is its exact octets
Alt-Svc: spdy%2F3="old.example.com:443"   # spdy/3 is registered, and not offered here
```
