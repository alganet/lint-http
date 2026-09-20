<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# The header fields a 304 owes the 200 it replaces

## Description

RFC 9110 §15.4.5 says two things about a `304 (Not Modified)`, and they pull in opposite directions. A sender **SHOULD NOT** generate representation metadata beyond a listed set — that is `status_304_representation_metadata`'s sentence — and, two paragraphs earlier, a server generating a 304 **MUST** generate any of `Content-Location`, `Date`, `ETag`, `Vary`, `Cache-Control` and `Expires` *"that would have been sent in a 200 (OK) response to the same request"*. This rule reads the MUST.

**The requirement is conditional, and the condition is not in the 304.** A response that omits `Vary` violates nothing unless the `200` it stands in for would have carried one, and no single message says what that hypothetical `200` holds. So this rule answers it with an observation instead: an earlier `200`, from the same client, for the same resource, answering **the same request** — same method, same target URI, and the same header fields but for the precondition that made this one conditional. Where no such exchange was seen, nothing is reported; a proxy that joins a conversation after the representation was stored has no antecedent to read and says so by staying quiet.

**"The same request" is read strictly.** Every request header field but the five §13.1 preconditions has to match, octet for octet. The fields at issue are the ones content negotiation moves — `Vary` is a statement about which request fields select the representation — so a looser comparison would be reasoning about a `200` the server never had occasion to send. What that costs is silence wherever a client changed anything else between the two requests, and silence is the right direction to be wrong in for a finding that ships at `error`.

**One finding per field**, each naming the field and the value the `200` sent, so an operator has the line to put back rather than a list to check.

**What the omission costs.** RFC 9111 §4.3.4 has a cache identify which stored responses a 304 freshens by the validators the 304 carries; where the new response carries none and the stored one has one, no stored response is identified for update at all — so a 304 that drops the `ETag` spends the round trip and freshens nothing. For the other five the loss is §15.4.5's own first paragraph: the recipient is being redirected to use its stored representation *"as if it were the content of a 200 (OK) response"*, and a field that response would have carried is one it does not get.

**Not folded into `status_304_representation_metadata`.** That rule is decided by the status code and the fields beside it, in one message, and says so three times over; this one cannot be answered without a second exchange. Same section, same status code, opposite direction, and different evidence.

## Violations

- [status_304_field_missing](../violations/status_304_field_missing.md) — A 304 omits a header field the 200 it stands in for carried

## Specifications

- [RFC 9110 §15.4.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.5): 304 Not Modified — the fields a 304 MUST send, the SHOULD NOT against any other representation metadata unless it guides cache updates, and the response being terminated by the end of the header section
- [RFC 9111 §4.3.4](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.3.4): Freshening Stored Responses upon Validation — a cache identifies what a 304 updates by the validators the 304 carries, and where it carries none while the stored response has one, no stored response is identified and the revalidation freshens nothing

## Configuration

```toml
[rules.status_304_required_fields]
enabled = true
```

## Examples

### ✅ Good — the 304 repeats every listed field the 200 carried

```http
GET /a HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Date: Mon, 01 Jan 2024 00:00:00 GMT
ETag: "abc"
Vary: Accept-Encoding

GET /a HTTP/1.1
Host: example.com
If-None-Match: "abc"

HTTP/1.1 304 Not Modified
Date: Mon, 01 Jan 2024 00:00:01 GMT
ETag: "abc"
Vary: Accept-Encoding
```

### ✅ Good — a field the 200 did not send either is not one the 304 owes

```http
GET /a HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Date: Mon, 01 Jan 2024 00:00:00 GMT
ETag: "abc"

GET /a HTTP/1.1
Host: example.com
If-None-Match: "abc"

HTTP/1.1 304 Not Modified
Date: Mon, 01 Jan 2024 00:00:01 GMT
ETag: "abc"
```

### ❌ Bad — the negotiation the 200 announced, dropped from the 304

```http
GET /a HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Date: Mon, 01 Jan 2024 00:00:00 GMT
ETag: "abc"
Vary: Accept-Encoding

GET /a HTTP/1.1
Host: example.com
If-None-Match: "abc"

HTTP/1.1 304 Not Modified
Date: Mon, 01 Jan 2024 00:00:01 GMT
ETag: "abc"
```

### ❌ Bad — the validator dropped, so RFC 9111 §4.3.4 freshens no stored response

```http
GET /a HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Date: Mon, 01 Jan 2024 00:00:00 GMT
ETag: "abc"
Cache-Control: max-age=60

GET /a HTTP/1.1
Host: example.com
If-None-Match: "abc"

HTTP/1.1 304 Not Modified
Date: Mon, 01 Jan 2024 00:00:01 GMT
```
