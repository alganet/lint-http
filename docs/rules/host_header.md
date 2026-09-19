<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Host Header

## Description

This rule reads the request's `Host` header field: whether it is there, whether it is there once, and whether its value is what `Host = uri-host [ ":" port ]` generates.

- A request that carries no `Host` field is reported **unless it is an HTTP/2 or HTTP/3 request that sent an `:authority` pseudo-header** — RFC 9110 §7.2's MUST is written with that exception, and RFC 9112 §3.2's is written for HTTP/1.1 messages. An HTTP/1.1 request in absolute-form is not exempt: RFC 9112 §3.2.2 requires the field there too.
- `Host` is not a list field, so two field lines of it are not one value; RFC 9110 §5.3 forbids a sender from generating them and RFC 9112 §3.2 has the recipient answer 400.
- The value must be a `uri-host` (RFC 3986 §3.2.2) and, if a port follows the colon, a port. An IPv6 address must be inside square brackets — that is the only thing distinguishing an IP literal from a registered name.
- A userinfo subcomponent and its `@` are reported: RFC 9112 §3.2 requires the field value to be the authority component *excluding* them.

Three things this rule deliberately does **not** report:

- **An empty field value.** `reg-name` is `*( unreserved / pct-encoded / sub-delims )`, so a host of no characters is one, and RFC 9112 §3.2 *requires* an empty `Host` when the target URI's authority component is missing or undefined. A server facing one reconstructs an empty authority and may reject the request (RFC 9112 §3.3), but nothing makes the client's field a syntax error.
- **A port outside the TCP range.** The production is `port = *DIGIT` (RFC 3986 §3.2.3) — no lower bound, no upper bound, and zero digits is a port, which is why `Host: example.com:0`, `Host: example.com:99999` and `Host: example.com:` are not findings here. `Host: example.com:abc` is, because it is not `*DIGIT`.
- **Where the field sits in the header section.** RFC 9110 §7.2 says a user agent that sends `Host` SHOULD send it as the first field, and RFC 9110 §5.3 calls it good practice; the captured transaction holds its fields in a map whose iteration order is not the order they arrived in, so no check here can decide it.

## Violations

- [field_line_duplicated](../violations/field_line_duplicated.md) — A field is written on more lines than its definition allows
- [host_missing](../violations/host_missing.md) — A request names its authority in neither Host nor :authority
- [host_userinfo_forbidden](../violations/host_userinfo_forbidden.md) — A Host field value carries the userinfo subcomponent
- [percent_encoding_digits_missing](../violations/percent_encoding_digits_missing.md) — Percent-encoding stops before its two hexadecimal digits
- [percent_encoding_malformed](../violations/percent_encoding_malformed.md) — Percent-encoding is not two hexadecimal digits
- [uri_host_bracket_forbidden](../violations/uri_host_bracket_forbidden.md) — Host holds a square bracket outside an IP literal
- [uri_host_character_forbidden](../violations/uri_host_character_forbidden.md) — Host holds a character outside the registered-name alphabet
- [uri_host_closing_bracket_missing](../violations/uri_host_closing_bracket_missing.md) — Host opens an IP literal and never closes it
- [uri_host_ip_literal_delimiter_missing](../violations/uri_host_ip_literal_delimiter_missing.md) — An IPv6 address is written without the brackets that mark it
- [uri_host_ip_literal_malformed](../violations/uri_host_ip_literal_malformed.md) — Host brackets something that is not an IP literal
- [uri_port_character_forbidden](../violations/uri_port_character_forbidden.md) — Port holds a character that is not a digit

## Specifications

- [RFC 9110 §7.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.2): Host and :authority — `Host = uri-host [ ":" port ]`, the MUST to generate the field, and the `:authority` pseudo-header the MUST excepts
- [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3): Field Order — a sender MUST NOT write multiple field lines of one name, in the headers or the trailers, unless at least one alternative of the field's definition allows the lines to be recombined as a comma-separated list
- [RFC 9112 §3.2](https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2): Request Target — a `Host` in every HTTP/1.1 request, a value identical to the target URI's authority *excluding* the userinfo and its `@`, an empty value where the target has no authority, and the 400 a server owes a request with none or with two
- [RFC 3986 §3.2.2](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.2): Host — `host = IP-literal / IPv4address / reg-name`, where the square brackets of the IP literal are the only ones the URI syntax admits anywhere
- [RFC 3986 §3.2.3](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.3): Port — `port = *DIGIT`, which has no lower bound, no upper bound, and admits the empty string
- [RFC 3986 §2.1](https://www.rfc-editor.org/rfc/rfc3986.html#section-2.1): Percent-Encoding — `pct-encoded = "%" HEXDIG HEXDIG`, the two digits every `%` still owes

## Configuration

```toml
[rules.host_header]
enabled = true
```

## Examples

### ✅ Good A registered name and a port

```http
GET /path HTTP/1.1
Host: example.com:8080
```

### ✅ Good An IPv6 literal, inside the brackets that identify it

```http
GET /path HTTP/1.1
Host: [::1]:443
```

### ✅ Good A port no TCP connection could use is still `*DIGIT`

```http
GET /path HTTP/1.1
Host: example.com:99999
```

### ❌ Bad A port that is not digits

```http
GET /path HTTP/1.1
Host: example.com:abc
```

### ❌ Bad An IPv6 address with nothing marking where it ended

```http
GET /path HTTP/1.1
Host: fe80::1
```

### ❌ Bad The authority component, userinfo and all

```http
GET /path HTTP/1.1
Host: user:pass@example.com
```

### ❌ Bad A character no host production generates

```http
GET /path HTTP/1.1
Host: exa mple.com
```

### ❌ Bad Two field lines of a field that does not recombine as a list

```http
GET /path HTTP/1.1
Host: a.example
Host: b.example
```

### ❌ Bad An HTTP/1.1 request that sent its authority in neither of the two places it can travel

```http
GET /path HTTP/1.1
Accept: text/html
```
