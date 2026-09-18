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

## Violations

- [forwarded_element_whitespace_forbidden](../violations/forwarded_element_whitespace_forbidden.md) — Forwarded element holds whitespace its grammar does not admit
- [forwarded_pair_equals_missing](../violations/forwarded_pair_equals_missing.md) — Forwarded pair is written without its '='
- [forwarded_pair_value_empty](../violations/forwarded_pair_value_empty.md) — Forwarded pair is written with no value after its '='
- [forwarded_parameter_duplicated](../violations/forwarded_parameter_duplicated.md) — Forwarded element names one parameter more than once
- [forwarded_response_forbidden](../violations/forwarded_response_forbidden.md) — Response carries a Forwarded field
- [list_member_empty](../violations/list_member_empty.md) — List holds an empty element
- [list_member_missing](../violations/list_member_missing.md) — List with a one-element floor holds no element
- [node_ipv4_address_malformed](../violations/node_ipv4_address_malformed.md) — Node identifier is digits and dots that are not an IPv4 address
- [node_ipv6_address_malformed](../violations/node_ipv6_address_malformed.md) — Node identifier brackets something that is not an IPv6 address
- [node_ipv6_brackets_missing](../violations/node_ipv6_brackets_missing.md) — Node identifier holds an IPv6 address without its square brackets
- [node_ipv6_closing_bracket_missing](../violations/node_ipv6_closing_bracket_missing.md) — Node identifier opens an IPv6 literal and never closes it
- [node_ipv6_representation_invalid](../violations/node_ipv6_representation_invalid.md) — Node identifier writes an IPv6 address outside the recommended representation
- [node_malformed](../violations/node_malformed.md) — Node identifier derives from no alternative of the production
- [node_port_malformed](../violations/node_port_malformed.md) — Node identifier holds something that is not a node-port
- [percent_encoding_digits_missing](../violations/percent_encoding_digits_missing.md) — Percent-encoding stops before its two hexadecimal digits
- [percent_encoding_malformed](../violations/percent_encoding_malformed.md) — Percent-encoding is not two hexadecimal digits
- [quoted_pair_malformed](../violations/quoted_pair_malformed.md) — Escape is not a quoted-pair
- [quoted_string_control_character_forbidden](../violations/quoted_string_control_character_forbidden.md) — Quoted-string holds a control character
- [quoted_string_delimiter_missing](../violations/quoted_string_delimiter_missing.md) — Quoted-string is missing one of its DQUOTEs
- [quoted_string_quote_escape_missing](../violations/quoted_string_quote_escape_missing.md) — Quoted-string holds an unescaped DQUOTE
- [token_character_forbidden](../violations/token_character_forbidden.md) — Token holds a character outside tchar
- [token_empty](../violations/token_empty.md) — Token is written with no characters in it
- [token_whitespace_or_control_forbidden](../violations/token_whitespace_or_control_forbidden.md) — Token holds whitespace or a control character
- [uri_host_bracket_forbidden](../violations/uri_host_bracket_forbidden.md) — Host holds a square bracket outside an IP literal
- [uri_host_character_forbidden](../violations/uri_host_character_forbidden.md) — Host holds a character outside the registered-name alphabet
- [uri_host_closing_bracket_missing](../violations/uri_host_closing_bracket_missing.md) — Host opens an IP literal and never closes it
- [uri_host_ip_literal_malformed](../violations/uri_host_ip_literal_malformed.md) — Host brackets something that is not an IP literal
- [uri_port_character_forbidden](../violations/uri_port_character_forbidden.md) — Port holds a character that is not a digit
- [uri_scheme_character_forbidden](../violations/uri_scheme_character_forbidden.md) — URI scheme holds a character outside letters, digits, '+', '-' and '.'
- [uri_scheme_empty](../violations/uri_scheme_empty.md) — URI scheme is empty
- [uri_scheme_leading_letter_missing](../violations/uri_scheme_leading_letter_missing.md) — URI scheme does not begin with a letter

## Specifications

- [RFC 7239 §4](https://www.rfc-editor.org/rfc/rfc7239.html#section-4): The field's grammar, the case-insensitivity of parameter names, the MUST NOT on naming a parameter twice in one element, and the sentence restricting the field to requests
- [RFC 7239 §6](https://www.rfc-editor.org/rfc/rfc7239.html#section-6): `node` — an IPv4 address, a bracketed IPv6 address, `unknown` or an obfuscated identifier, each optionally followed by a `node-port`
- [RFC 7239 §6.1](https://www.rfc-editor.org/rfc/rfc7239.html#section-6.1): How an `IPv6address` is spelled in a node identifier: always in square brackets, and following RFC 5952's textual representation recommendations
- [RFC 7239 §5](https://www.rfc-editor.org/rfc/rfc7239.html#section-5): The four registered parameters. `host` MUST conform to the Host ABNF and `proto` to a URI scheme name; extension parameters SHOULD be registered, in a registry this rule does not hold
- [RFC 7239 §8.2](https://www.rfc-editor.org/rfc/rfc7239.html#section-8.2): Why a response must not carry the field: it reveals the whole proxy chain to the client
- [RFC 9110 §7.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.2): `Host = uri-host [ ":" port ]`, which §5.3 makes the syntax of a `host` parameter
- [RFC 3986 §3.1](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.1): Scheme — `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`, the name before the first colon
- [RFC 3986 §3.2.2](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.2): Host — `host = IP-literal / IPv4address / reg-name`, where the square brackets of the IP literal are the only ones the URI syntax admits anywhere
- [RFC 3986 §3.2.3](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.3): Port — `port = *DIGIT`, which has no lower bound, no upper bound, and admits the empty string
- [RFC 3986 §2.1](https://www.rfc-editor.org/rfc/rfc3986.html#section-2.1): Percent-Encoding — `pct-encoded = "%" HEXDIG HEXDIG`, the two digits every `%` still owes
- [RFC 9110 §5.6.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.4): `quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE` — the two delimiters, the class between them, and the backslash escape
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): Tokens — `token = 1*tchar`, and the fifteen punctuation marks besides the digits and letters that `tchar` admits
- [RFC 9110 §5.6.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1): The list construct — `1#element => element *( OWS "," OWS element )`, and the sender's MUST NOT against an empty element
- [RFC 9110 §5.6.1.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.2): The values a `1#element` production does not generate — the empty value among them — beside the recipient's instruction to ignore empty elements

## Configuration

```toml
[rules.forwarded_header_valid]
enabled = true
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
