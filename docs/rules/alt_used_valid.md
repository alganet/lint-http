<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Alt Used Valid

## Description

Reads the `Alt-Used` header field: whether it is there once, and whether its value is what `Alt-Used = uri-host [ ":" port ]` generates.

**RFC 7838 defines two header fields and this is the other one.** `Alt-Svc` is the advertisement a server sends and has three rules reading it; `Alt-Used` is what a client puts on a request to name the alternative service it took, and nothing read it. Two instruments could not have said so: coverage counts entries, and a field with no reader has no entry to be uncovered, while a census of field names asks only of names that appeared on some wire — and `Alt-Used` appears on none a proxy in front of an origin records, because it names the alternative the client reached instead.

**Every finding below is the authority's, not this field's.** § 5 writes the value as two productions RFC 3986 defines and adds not a word to either, so a bracket in the wrong place, a character no `reg-name` admits and a port that is not `*DIGIT` are reported under the same ids a `Host` draws them under. That is deliberate: an operator who has tuned `uri_host_character_forbidden` has tuned it here too, and the message names the field so the line is findable.

Three things this rule does **not** report, each because the sentence that would license it is `Host`'s and not this field's:

- **An absent `Alt-Used`.** RFC 9110 §7.2 makes `Host` mandatory; RFC 7838 §5 asks for `Alt-Used` only *when using an alternative service*, which is the next point.
- **A userinfo subcomponent.** RFC 9112 §3.2 names the `@` for `Host` in a MUST of its own, so `host_header` reports it as such. Here the `@` is simply a character `uri-host` does not admit, and it is reported as one.
- **An empty field value.** `reg-name` is `*( unreserved / pct-encoded / sub-delims )`, so a host of no characters derives from the grammar. RFC 9112 §3.2 goes further for `Host` and *requires* the empty value in one case; RFC 7838 neither requires nor forbids it, and inventing a prohibition because the field would identify nothing is a requirement no document states.

**The SHOULD in §5 is declined, and the antecedent is why.** "When using an alternative service, clients SHOULD include an Alt-Used header field in all requests" is a real obligation on a real sender, and a captured exchange does not record whether the connection it arrived on was an alternative service rather than the origin. The requirement is unobservable from a message, which is a different thing from absent; a rule that reported every request without the field would report every client that never used an alternative at all.

**Both directions are read and nothing is claimed about direction.** §5 describes a field used in requests and forbids one in a response nowhere, exactly as §12.5.2 does for `Accept-Charset`. A response carrying an `Alt-Used` has its value checked, because a malformed authority is malformed wherever it appears, and the finding is attributed to the server that wrote it.

**The value is read as the octets the sender wrote**, one `char` per octet: nothing in this grammar is a quoted-string, so no octet outside visible US-ASCII is legal anywhere in it, and every one of them lands inside a production that already has an id for it.

## Violations

- [field_line_duplicated](../violations/field_line_duplicated.md) — A field is written on more lines than its definition allows
- [percent_encoding_digits_missing](../violations/percent_encoding_digits_missing.md) — Percent-encoding stops before its two hexadecimal digits
- [percent_encoding_malformed](../violations/percent_encoding_malformed.md) — Percent-encoding is not two hexadecimal digits
- [uri_host_bracket_forbidden](../violations/uri_host_bracket_forbidden.md) — Host holds a square bracket outside an IP literal
- [uri_host_character_forbidden](../violations/uri_host_character_forbidden.md) — Host holds a character outside the registered-name alphabet
- [uri_host_closing_bracket_missing](../violations/uri_host_closing_bracket_missing.md) — Host opens an IP literal and never closes it
- [uri_host_ip_literal_delimiter_missing](../violations/uri_host_ip_literal_delimiter_missing.md) — An IPv6 address is written without the brackets that mark it
- [uri_host_ip_literal_malformed](../violations/uri_host_ip_literal_malformed.md) — Host brackets something that is not an IP literal
- [uri_port_character_forbidden](../violations/uri_port_character_forbidden.md) — Port holds a character that is not a digit

## Specifications

- [RFC 7838 §5](https://www.rfc-editor.org/rfc/rfc7838.html#section-5): The Alt-Used HTTP Header Field: `Alt-Used = uri-host [ ":" port ]`, the same two productions `Host` prints, carried on a request to name the alternative service in use. The section adds no constraint of its own to either production, and its one requirement on a sender — that a client using an alternative service send the field — has an antecedent a message does not record
- [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3): Field Order — a sender MUST NOT write multiple field lines of one name, in the headers or the trailers, unless at least one alternative of the field's definition allows the lines to be recombined as a comma-separated list
- [RFC 3986 §3.2.2](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.2): Host — `host = IP-literal / IPv4address / reg-name`, where the square brackets of the IP literal are the only ones the URI syntax admits anywhere
- [RFC 3986 §3.2.3](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.3): Port — `port = *DIGIT`, which has no lower bound, no upper bound, and admits the empty string
- [RFC 3986 §2.1](https://www.rfc-editor.org/rfc/rfc3986.html#section-2.1): Percent-Encoding — `pct-encoded = "%" HEXDIG HEXDIG`, the two digits every `%` still owes

## Configuration

```toml
[rules.alt_used_valid]
enabled = true
```

## Examples

### ✅ Good The alternative's host, as RFC 7838 §5's own example writes it

```http
GET /thing HTTP/1.1
Host: origin.example.com
Alt-Used: alternate.example.net
```

### ✅ Good A port follows the one colon that delimits one

```http
GET /thing HTTP/1.1
Host: origin.example.com
Alt-Used: alternate.example.net:443
```

### ✅ Good An IPv6 literal, inside the brackets that identify it

```http
GET /thing HTTP/1.1
Host: origin.example.com
Alt-Used: [2001:db8::1]:443
```

### ❌ Bad An IPv6 address with nothing marking where it stopped

```http
GET /thing HTTP/1.1
Host: origin.example.com
Alt-Used: 2001:db8::1
```

### ❌ Bad A space is in no host production

```http
GET /thing HTTP/1.1
Host: origin.example.com
Alt-Used: alternate example.net
```

### ❌ Bad `port = *DIGIT`, and these are not digits

```http
GET /thing HTTP/1.1
Host: origin.example.com
Alt-Used: alternate.example.net:https
```

### ❌ Bad The field is not a list, so two lines are not one value

```http
GET /thing HTTP/1.1
Host: origin.example.com
Alt-Used: a.example
Alt-Used: b.example
```
