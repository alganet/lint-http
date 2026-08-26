<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Early Data Header Safe Method

## Description

Reports a request that was conveyed in TLS early data — a request carrying an `Early-Data` header field — under a method this deployment does not list as safe. RFC 8470 §4: "Absent other information, clients MAY send requests with safe HTTP methods … in early data when it is available and MUST NOT send unsafe methods (or methods whose safety is not known) in early data." Early data can be captured and replayed by an attacker, so a request that changes state may take effect more than once.

**The field's presence is the signal, not its value.** RFC 8470 §5.1 gives the field one valid value, `1`, and then says what a server does with anything else: "Multiple or invalid instances of the header field MUST be treated as equivalent to a single instance with a value of 1 by a server." So `Early-Data: 0`, an empty value, a value that is not US-ASCII, and two field lines all describe the same request — one a server must treat as having arrived through early data. The value and the line count are each reported separately, as what they are.

**The sender of the message is usually not the party that broke the requirement.** §5.1: "A request that is marked with Early-Data was sent in early data on a previous hop", and the field "is not intended for use by user agents (that is, the original initiator of a request)" — an intermediary forwarding a request before its TLS handshake completed MUST add it. So a finding here says an unsafe method entered early data somewhere along the chain; which hop put it there is not in the message.

**`safe_methods` is required, and the reason is that safety is a registry field.** RFC 9110 §16.1.1 makes `Safe ("yes" or "no")` a mandatory part of every method registration, and entries are added by IETF Review — `GET`, `HEAD`, `OPTIONS` and `TRACE` are only the ones RFC 9110 itself defines, while `PRI`, `PROPFIND`, `QUERY`, `REPORT` and `SEARCH` are registered safe by other documents. A list compiled into this rule would be a snapshot of that registry presented as though it were the grammar. The array is also where a deployment records what it knows about its own methods, which is the state §4's sentence opens with — "Absent other information".

Methods are matched exactly. RFC 9110 §9.1: "The method token is case-sensitive", so `get` is not `GET` but a method this specification does not define, and §4's parenthetical — "or methods whose safety is not known" — is what covers it. A method absent from the array is reported for that reason, not for being unsafe.

**Three further sentences of §5.1 are enforced here, because this rule is the field's only reader.** A client may send at most one instance. The field MUST NOT appear in a response. And it MUST NOT be named as a connection-option in a `Connection` header field, which would have every intermediary strip the one field §5.1 forbids removing. The remaining placement — the field arriving in a trailer section — is `message_trailer_fields_validity`'s finding, since that is where RFC 9110 §6.5.1 is applied.

**Not checked here.** Whether a request was in fact sent in early data when no field marks it: a user agent that sends its own request in early data "does not need to include the Early-Data header field", so an unmarked early-data request is invisible to any observer of the message. Whether a server answered a request it could not safely process with 425 (Too Early), which turns on the origin's own judgement of replay risk for a resource. And whether "other information" existed: an out-of-band agreement that a particular resource tolerates replay leaves no trace in the message, which is why the deployment's array is the place to record it.

## Specifications

- [RFC 8470 §4](https://www.rfc-editor.org/rfc/rfc8470.html#section-4): Using Early Data in HTTP Clients — the MUST NOT that licenses this rule, and it covers two sets: unsafe methods, and methods whose safety is not known. It opens "Absent other information", an out-of-band state no message records
- [RFC 8470 §5.1](https://www.rfc-editor.org/rfc/rfc8470.html#section-5.1): The Early-Data Header Field — one valid value, at most one instance, invalid or repeated instances read as a single "1", added by an intermediary rather than by the user agent, and forbidden in a Connection field, in a response, and in a request's trailer section
- [RFC 8470 §5.2](https://www.rfc-editor.org/rfc/rfc8470.html#section-5.2): The 425 (Too Early) Status Code — what a server sends instead of processing a marked request it judges too risky. Nothing here reads it: whether a given resource tolerates replay is knowledge only the origin has
- [RFC 9110 §9.2.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.1): Safe Methods — the property RFC 8470 §4 names. GET, HEAD, OPTIONS and TRACE are the safe methods this document defines, which is a smaller set than the safe methods there are
- [RFC 9110 §16.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-16.1.1): Method Registry — every registration MUST carry a Safe field, and entries are added by IETF Review. This is why the safe set is configured rather than compiled in
- [IANA HTTP Method Registry](https://www.iana.org/assignments/http-methods/http-methods.xhtml): The registry itself. Its Safe column held GET, HEAD, OPTIONS, PRI, PROPFIND, QUERY, REPORT, SEARCH and TRACE when config_example.toml's array was written

## Configuration

```toml
[rules.early_data_header_safe_method]
enabled = true
severity = "warn"
# The methods this deployment knows to be safe. Safety is a required field of every
# entry in the IANA "Hypertext Transfer Protocol (HTTP) Method Registry" (RFC 9110
# §16.1.1), which grows by IETF Review, so the set below is that registry's `Safe: yes`
# column and not a grammar. GET, HEAD, OPTIONS and TRACE are the four RFC 9110 itself
# defines; the rest are registered safe by RFC 9113, RFC 4918, RFC 10008, RFC 3253 and
# RFC 5323. Add a private method here when this deployment knows it to be safe — RFC
# 8470 §4's requirement opens "Absent other information", and this array is where that
# information goes.
safe_methods = [
  "GET",
  "HEAD",
  "OPTIONS",
  "PRI",
  "PROPFIND",
  "QUERY",
  "REPORT",
  "SEARCH",
  "TRACE",
]
```

## Examples

### ✅ Good RFC 8470 §5.1's own example of the field

```http
GET /resource HTTP/1.0
Host: example.com
Early-Data: 1
```

### ❌ Bad an unsafe method conveyed in early data

```http
POST /submit HTTP/1.1
Host: example.com
Early-Data: 1
```

### ❌ Bad a value a server still reads as "1", so the request is early data all the same

```http
DELETE /item/7 HTTP/1.1
Host: example.com
Early-Data: 0
```

### ❌ Bad naming the field as a connection-option has every intermediary strip it

```http
GET /resource HTTP/1.1
Host: example.com
Connection: early-data
Early-Data: 1
```
