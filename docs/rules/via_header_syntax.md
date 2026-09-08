<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Via Header Syntax

## Description

Parses the `Via` field of a request and of a response — every field line of one section joined into the single list they are — against RFC 9110 §7.6.3's grammar: `Via = #( received-protocol RWS received-by [ RWS comment ] )`, where `received-protocol` is a `protocol-version` optionally preceded by a `protocol-name` and a slash (§7.8 makes both tokens), `received-by = pseudonym [ ":" port ]`, and `pseudonym = token`. 

Three consequences of that grammar are worth stating before the rule is enabled. **`received-by` is a token, not a host.** RFC 9110 removed `uri-host` from the production (Appendix B.2) on the grounds that a pseudonym encompasses it, so a bracketed IPv6 literal — `Via: 1.1 [2001:db8::1]:8080`, which RFC 7230's grammar admitted — has no spelling here and is reported. **A port is `*DIGIT`** (RFC 3986 §3.2.3): it carries no range, so `:0` and `:99999` are syntax-conforming, and so is a colon with no digits after it. **An empty field value is a list of no members** and is not reported, while an empty member — including one written at a line boundary, since the lines of one section are one list — is RFC 9110 §5.6.1.1's sender MUST NOT. 

A member's optional comment is parsed as §5.6.5's `comment`: nested parentheses and backslash escapes are honoured, `obs-text` inside it is permitted, and it must be the last thing in the member and separated from the `received-by` by whitespace. 

What the rule does not judge: whether a proxy sent a `Via` at all. §7.6.3's MUST is about each message a proxy *forwards*, and a capture does not record whether the message arrived through an intermediary, so an absent field is not evidence of anything. Neither are the section's requirements about combining members (a sender MUST NOT combine members with different received-protocols, and SHOULD NOT combine members outside one organization) or the firewall SHOULD NOT: a combined member and a member that was always one are the same octets, and no field records the topology the other sentences are about.

## Specifications

- [RFC 9110 §7.6.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.6.3): The `Via` grammar this rule parses, the sentence that puts the field in both directions, and the requirements about forwarding and combining that a single captured message cannot answer
- [RFC 9110 §7.8](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.8): `received-protocol` points here for its two halves: `protocol-name = token` and `protocol-version = token`
- [RFC 9110 §B.2](https://www.rfc-editor.org/rfc/rfc9110.html#appendix-B.2): Why a `received-by` is a token: RFC 9110 removed `uri-host` from the production, which is what makes a bracketed IPv6 literal a finding here and not under RFC 7230
- [RFC 9110 §5.6.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.5): Comments — `comment = "(" *( ctext / quoted-pair / comment ) ")"`, the `ctext` class, and the self-reference that makes a comment nestable
- [RFC 9110 §5.6.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1): The list construct — `1#element => element *( OWS "," OWS element )`, and the sender's MUST NOT against an empty element
- [RFC 9110 §5.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.2): Several `Via` lines in one section are one field value, which is why the members are counted after they are joined
- [RFC 3986 §3.2.3](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.3): Port — `port = *DIGIT`, which has no lower bound, no upper bound, and admits the empty string
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): Tokens — `token = 1*tchar`, and the fifteen punctuation marks besides the digits and letters that `tchar` admits
- [RFC 9110 §5.6.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.4): `quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE` — the two delimiters, the class between them, and the backslash escape

## Configuration

```toml
[rules.via_header_syntax]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good The chain §7.6.3 prints, and the collapsed form it prints beside it

```http
GET /index.html HTTP/1.1
Via: 1.0 fred, 1.1 p.example.net
Via: 1.0 ricky, 1.1 mertz, 1.0 lucy
```

### ✅ Good A named protocol, a port, and a comment naming the software

```http
GET /index.html HTTP/1.1
Via: HTTP/1.1 proxy.example.com:8080 (squid/5.7)
```

### ❌ Bad A member with a received-protocol and no received-by

```http
GET /index.html HTTP/1.1
Via: 1.1
```

### ❌ Bad `@` is not a tchar, and both halves of a received-protocol are tokens

```http
GET /index.html HTTP/1.1
Via: HT@P/1.1 proxy.example.com
```

### ❌ Bad A port is digits, however few

```http
GET /index.html HTTP/1.1
Via: 1.1 example.com:port
```

### ❌ Bad An empty list member, which a sender must not generate

```http
GET /index.html HTTP/1.1
Via: 1.1 example.com, , 1.0 proxy
```

### ❌ Bad `received-by` is a pseudonym, and RFC 9110 removed the host that admitted brackets

```http
GET /index.html HTTP/1.1
Via: 1.1 [2001:db8::1]:8080
```
