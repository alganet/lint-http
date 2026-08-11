<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Client Expect Header Valid

## Description

Reads a request's `Expect` field as `#expectation`, where each member is `token [ "=" ( token / quoted-string ) parameters ]`, and reports the client requirements RFC 9110 §10.1.1 places on it.

**A 100-continue expectation on a request with no content is a MUST NOT.** §10.1.1 says so in one line, and the expectation asks a server to decide about content the message never carried. Content is the octet stream left once framing is removed, so the captured count answers when there is one and the sender's `Content-Length` answers otherwise; a chunked request whose only chunk is the terminator carries none. Where a capture records neither, this rule reports — unlike the rules that report content being *present*, which stay silent on the same silence. The proxy always records the count, so that gap belongs to captures written elsewhere.

**A repeat of a request the chain answered with 417 is reported.** §10.1.1 asks a client that receives 417 to repeat without the expectation, since the status only means the response chain does not support expectations. The comparison is against the most recent exchange for this resource *using this method* — a request with another method is not the one being repeated.

**A value or parameters on `100-continue` is advice, not a violation.** The grammar admits both on any expectation and the specification says only that it defines none for this one. What it costs is real: a recipient matching the member against `100-continue` sees a different member, which §10.1.1 lets it answer with 417.

**Other expectation names are not reported.** `expectation` is a `token` with no registry behind it, and the only consequence the specification states is a server's MAY to answer 417.

**Syntax is judged as written and as one list.** The field lines are joined before the members are counted, because `#expectation` makes them one list and a member may be written at a line boundary. The value is read octet by octet rather than decoded, since an expectation's value may be a `quoted-string` and `qdtext` admits `obs-text` — refusing the field would hide the legal value and the illegal one alike. `Expect:` with nothing after it is a conforming *empty list* (Appendix A writes the whole value as optional) and is not reported; an empty element inside a list is §5.6.1.1's sender MUST NOT and is. That the field is a list at all is recent: RFC 7231 wrote it as the bare string `100-continue`, and RFC 9110 §B.3 records restoring the list grammar.

**Whitespace is not tolerated where the grammar has none.** `expectation` puts no `OWS` around its `=`, and §5.6.6's note says parameters allow none around theirs either, so `a = b` and `a=b; c = d` are reported. §2.2 is what makes a value the ABNF does not generate a finding rather than a preference.

**Not checked here:** whether a client that waited for a 100 (Continue) sent the expectation, and how long it waited — §10.1.1 states both as client requirements, and neither the waiting nor its duration appears in a captured message. The server requirements in the same section (ignoring the expectation in an HTTP/1.0 request, sending a final status after a 100) are about a response and are outside a rule scoped to the client. `Expect` in a *response* is not reported: §10.1 defines these as request header fields, but no sentence forbids sending one elsewhere.

## Specifications

- [RFC 9110 §10.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.1): Expect: the field's grammar, the one expectation this specification defines, and the four client requirements — of which the MUST NOT on a request without content and the SHOULD after a 417 are the two a captured message can measure
- [RFC 9110 §A](https://www.rfc-editor.org/rfc/rfc9110.html#appendix-A): Collected ABNF for senders: `Expect` with its list construct expanded, which is where the whole value being optional is written out
- [RFC 9110 §5.6.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1): List sender requirements — the MUST NOT behind the empty-element finding
- [RFC 9110 §5.6.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.6): `parameters`, the production this rule's transcribed grammar used to end one term short of
- [RFC 9110 §15.5.18](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.18): 417 Expectation Failed — what the status the repeat check reads means
- [RFC 9110 §2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2): Requirements Notation — where the sentence that makes an element the ABNF does not generate a violation lives, rather than §2.4 Error Handling
- [RFC 9110 §B.3](https://www.rfc-editor.org/rfc/rfc9110.html#appendix-B.3): Changes from RFC 7231: the list-based grammar for `Expect` was restored, and an expectation's parameters may be empty — two sentences that decide how this rule reads the field

## Configuration

```toml
[rules.client_expect_header_valid]
enabled = true
severity = "error"
```

## Examples

### ✅ Good A 100-continue expectation on a request that has content, an extension expectation whose value carries parameters, and an empty list — all three derive from `#expectation`

```http
PUT /upload HTTP/1.1
Host: example.com
Content-Type: text/plain
Content-Length: 8
Expect: 100-continue

abcdefgh

GET /foo HTTP/1.1
Host: example.com
Expect: hyper-fast=yes;level="9", slow

GET /bar HTTP/1.1
Host: example.com
Expect:
```

### ❌ Bad A 100-continue expectation with no content to weigh in on, an empty list element, and a member whose name is not a token

```http
GET /foo HTTP/1.1
Host: example.com
Expect: 100-continue
# No content, so RFC 9110 §10.1.1's client MUST NOT applies

GET /bar HTTP/1.1
Host: example.com
Expect: 100-continue, , slow
# The middle element is empty (RFC 9110 §5.6.1.1)

GET /baz HTTP/1.1
Host: example.com
Expect: a/b
# '/' is not a tchar, so 'a/b' is not a token
```
