<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Accept-Ranges Values Valid

## Description

Checks that an `Accept-Ranges` response header field is what RFC 9110 §14.3 defines it to be: a non-empty comma-separated list of range units, each of them a `token`.

**Any range unit name is accepted.** `range-unit = token`, names are case-insensitive, and §14.1 says they "are intended to be extensible". The "HTTP Range Unit Registry" holds two entries today — `bytes` and `none` — and adding a third takes IETF Review, not a change here, so `Accept-Ranges: pages` is not reported. This rule used to accept `bytes` and `none` only, "for practical compatibility", and called every other name an unexpected range-unit.

**An unregistered name is not reported either.** §14.1 says names "ought to be registered", which is weaker than SHOULD, and nothing follows from a client meeting a unit it does not know: §14.3 makes the whole field advice a client MAY ignore.

**Both of the field's sections are read, and the lines of each are joined.** §14.3 says `Accept-Ranges` MAY be sent in a trailer section, so a response that advertises only there is advertising. Within one section, `acceptable-ranges = 1#range-unit` makes several field lines one list, appended in order and separated by comma SP — a response saying `bytes` on one line and `none` on the next is saying both. The sections are not joined to each other: appending a field line to the one before it is defined within a field section, and a trailer arrives after the content as a section of its own.

**The list is measured as a sender's, not as a recipient's.** §5.6.1.2 tells recipients to parse and ignore empty list elements, which is what the shared list reader does and why it cannot answer this rule's question: §5.6.1.1 says "a sender MUST NOT generate empty list elements", so `Accept-Ranges: bytes,,none` is reported for the hole rather than counted as two units. A value with no non-empty element at all — `Accept-Ranges: ,` or an empty field line — is not `1#range-unit` either. An octet outside visible US-ASCII is reported for what it is: every character of a `token` is visible US-ASCII, so being valid UTF-8 does not make one admissible.

**`none` beside another unit is reported as advice, not as a violation.** §14.3 grants a MAY to a server that "does not support any kind of range request for the target resource" to send `Accept-Ranges: none`, and reserves the name for that purpose. A field that lists `none` next to a unit it does support says both things at once; no sentence forbids it, and a client will act on one of the two halves.

**What else it does not report.** A trailer section carrying the field rather than a header section — §14.3 prefers the header section, gives its reason, and attaches no modal. And a response whose next range request is answered in full: §14.3 says in as many words that a client "MUST NOT assume that receiving an Accept-Ranges field means that future range requests will return partial responses", which is addressed to the client and measures nothing about the response that carried the field.

## Specifications

- [RFC 9110 §14.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.3): `Accept-Ranges`: `acceptable-ranges = 1#range-unit`, sent in a response to indicate whether an upstream server supports range requests for the target resource. It grants a MAY to a server that "does not support any kind of range request for the target resource" to send `none`, and reserves that name for the purpose — the condition on the MAY is what makes `none` beside another unit worth reporting, and the absence of any prohibition is why the report is advice. The field MAY also be sent in a trailer section, which is where the second field section this rule reads comes from, and the preference for the header section carries no modal. The section's remaining sentences are addressed to clients: the field is advice a client MAY ignore, and a client MUST NOT read it as a promise about the next request
- [RFC 9110 §14.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.1): Range Units: `range-unit = token`, names case-insensitive, "intended to be extensible" — which is why no name is reported for being one this rule has not heard of. Registration is what names "ought to be" have, weaker than SHOULD, and this rule holds no registry to measure it with anyway
- [RFC 9110 §16.5.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-16.5.1): The "HTTP Range Unit Registry", which holds `bytes` and `none` today and takes IETF Review to add to. Those two entries are the two this rule used to accept as though they were the grammar
- [RFC 9110 §5.6.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1): Sender Requirements for the list construct: OWS on either side of each comma, and a sender MUST NOT generate empty list elements. §5.6.1.2 tells recipients the opposite — parse and ignore them — so the shared list reader, which drops them, cannot answer this rule's question, and a value with no non-empty element at all is among that section's own examples of an invalid `1#`
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): Tokens: `tchar` is "any VCHAR, except delimiters", so every character of a range unit name is visible US-ASCII. An octet outside that is reported for being outside the production and not for failing to decode as UTF-8, which refuses a perfectly good `é` for a reason that was never the point
- [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3): Field Order: multiple field lines of one name within a field section are combined in order, separated by comma SP, when the field's definition allows a comma-separated list — which `1#range-unit` is. So several `Accept-Ranges` lines are one list to read rather than a duplication to report, and the joining stops at the section boundary the sentence names

## Configuration

```toml
[rules.server_accept_ranges_values_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Accept-Ranges: bytes

HTTP/1.1 200 OK
Accept-Ranges: none

HTTP/1.1 200 OK
Accept-Ranges: BYTES
```

### ✅ Good (a range unit this rule does not have to know)

```http
HTTP/1.1 200 OK
Accept-Ranges: pages
```

### ❌ Bad (`none` says no range request is supported, beside a unit that is)

```http
HTTP/1.1 200 OK
Accept-Ranges: none, bytes
```

### ❌ Bad (a range unit is a token, and a space is not a token character)

```http
HTTP/1.1 200 OK
Accept-Ranges: b ytes
```
