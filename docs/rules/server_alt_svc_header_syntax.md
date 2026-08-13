<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Alt-Svc Header Syntax

## Description

Read an `Alt-Svc` response header field against the grammar RFC 7838 §3 prints for it:

```
Alt-Svc       = clear / 1#alt-value
clear         = %s"clear"; "clear", case-sensitive
alt-value     = alternative *( OWS ";" OWS parameter )
alternative   = protocol-id "=" alt-authority
protocol-id   = token ; percent-encoded ALPN protocol name
alt-authority = quoted-string ; containing [ uri-host ] ":" port
parameter     = token "=" ( token / quoted-string )
```

**The alt-authority is a `quoted-string`, and the DQUOTEs are the production.** Every example in RFC 7838 carries them, and the section says why: *"Note that the "quoted-string" syntax needs to be used because ":" is not an allowed character in "token"."* An unquoted `h2=example.com:443` is reported. Inside the quotes the content is asked for in prose rather than ABNF — *"an OPTIONAL uri-host …, a colon (":"), and a port number"* — so the host may be absent and the colon and the number may not.

**`clear` is the whole field value or it is nothing.** The top production is an alternation, so a value holding the keyword beside an alternative derives from neither half; RFC 7838 §3 calls that *"an invalid reply"* in its own parenthetical. The keyword is `%s"clear"`, a case-sensitive string, so `CLEAR` is not it and is read as an `alt-value` instead.

**A `protocol-id` is a percent-encoded ALPN protocol name, and three sentences constrain the spelling** — octets no `token` admits MUST be percent-encoded (including `%` itself, as `%25`), octets that *are* valid token characters MUST NOT be, and the hex digits MUST be uppercase. A `token` admits `%`, so a character scan sees none of these. They exist so that *"recipients can apply simple string comparison to match protocol identifiers"*, which two spellings of one name would defeat.

**A port above 65535 is reported; `0` is not.** The bound is not the grammar's — `port` is `*DIGIT` — but that an ALPN protocol name identifies a suite carried over a transport whose port registry is sixteen bits wide (RFC 6335 §6). `0` sits inside that namespace as a reserved edge value, and no sentence here makes a reserved port an invalid one.

**Parameters are read as `token "=" ( token / quoted-string )` and not looked up.** *"Unknown parameters MUST be ignored"*, so a name this rule does not recognise is not a defect. `persist` is the one exception, because §3.1 prints a syntax for it that is a single literal `"1"` and requires clients to ignore any other value. The `ma` parameter's own value is read by `server_alt_svc_h3_advertisement_valid`.

**Whitespace beside an `=` is reported.** RFC 7838 writes `OWS` in exactly one place — around the semicolon before a parameter — and the `#rule` it imports writes it around the commas. Both are gone by the time a half is read, so whitespace still touching an `=` is admitted by nothing. This is the opposite of a `BWS`, which is whitespace a grammar prints in order to tolerate.

**What this rule declines.** RFC 7838 §3 says that over HTTP/2 *"servers SHOULD instead send an ALTSVC frame"*, and the next sentence says *"Alt-Svc header fields remain valid in responses delivered over HTTP/2"*. The frame is not in a capture, HTTP/3 has no such frame at all and RFC 9114 §3.1.1 has an HTTP/3 server use this field, so the SHOULD is not reported. Nothing here reads *which* protocol a well-spelled `protocol-id` names — `server_alt_svc_protocol_iana_registered` decodes it back into its ALPN protocol name and asks that against a configured list.

## Specifications

- [RFC 7838 §3](https://www.rfc-editor.org/rfc/rfc7838.html#section-3): The Alt-Svc HTTP Header Field: the field's grammar, the `clear` keyword, the three percent-encoding constraints on a protocol-id, and the prose requiring a colon and a port inside the alt-authority
- [RFC 7838 §3.1](https://www.rfc-editor.org/rfc/rfc7838.html#section-3.1): Caching Alt-Svc Header Field Values: `persist = "1"` is the whole syntax of that parameter, and clients ignore any other value
- [RFC 7838 §1.1](https://www.rfc-editor.org/rfc/rfc7838.html#section-1.1): Notational Conventions: the field's terminals — `OWS`, `port`, `quoted-string`, `token`, `uri-host` — and the `#rule` extension are imported from RFC 7230, whose §3.2.3, §2.7, §3.2.6 and §7 are carried unchanged by RFC 9110 §5.6.3, §4.1, §5.6.4, §5.6.2 and §5.6.1
- [RFC 7838 §8](https://www.rfc-editor.org/rfc/rfc7838.html#section-8): Internationalization Considerations: an internationalized domain name in this field is written as A-labels
- [RFC 7838 §2](https://www.rfc-editor.org/rfc/rfc7838.html#section-2): Alternative Services Concepts: an alternative service is an ALPN protocol name, an RFC 3986 host and an RFC 3986 port, and the protocol name implies the transport the port is registered in
- [RFC 9110 §5.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6): Common Rules for Defining Field Values: `token`, `quoted-string`, `OWS` and the `#rule` list construct this field's grammar is built from, and the sender's MUST NOT against empty list elements
- [RFC 3986 §3.2](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2): Authority: `host` and `port`, the two productions the alt-authority's content is made of, and `pct-encoded` in §2.1
- [RFC 6335 §6](https://www.rfc-editor.org/rfc/rfc6335.html#section-6): Port Number Ranges: the sixteen-bit namespace that bounds the port, and the reserved edge values that are not thereby invalid

## Configuration

```toml
[rules.server_alt_svc_header_syntax]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Alt-Svc: h2=":443"; ma=2592000
Alt-Svc: h2="new.example.org:80"
Alt-Svc: h2="alt.example.com:8000", h2=":443"
Alt-Svc: h2="[::1]:443"; persist=1
Alt-Svc: clear
Alt-Svc: w%3Dx%3Ay#z=":443"
```

### ❌ Bad

```http
Alt-Svc: h2=example.com:443       # alt-authority is a quoted-string
Alt-Svc: h2="example.com"         # the colon and the port are not optional
Alt-Svc: h2="example.com:notaport" # port is *DIGIT
Alt-Svc: h2example.com:443        # no '=' in the alternative
Alt-Svc: h@=":443"                # '@' is no tchar
Alt-Svc: x%3dy=":443"             # hex digits are uppercase
Alt-Svc: %68%32=":443"            # a tchar is not percent-encoded
Alt-Svc: clear, h2=":443"         # clear beside an alternative
Alt-Svc: h2 = ":443"              # no OWS beside the '='
Alt-Svc: h2=":443"; persist=2     # persist's only value is "1"
Alt-Svc: ,                        # empty list element
```
