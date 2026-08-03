<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Accept and Content-Type Negotiation

## Description

Report a response whose `Content-Type` is not covered by any `media-range` the request's `Accept` header listed with a non-zero weight — `Accept: application/json` answered with `Content-Type: text/html`. The suggested remedies are the two the specification names: send a representation the client asked for, or say so with `406 (Not Acceptable)`.

**This is advice, not a conformance check, and the specification is explicit about it.** RFC 9110 §12.4.1 gives the origin server the choice in as many words: when no available representation is acceptable it "can either honor the header field by sending a 406 (Not Acceptable) response or disregard the header field by treating the response as if it is not subject to content negotiation". §12.1 says the same from the other side — a user agent "cannot rely on proactive negotiation preferences being consistently honored". So **a message this rule reports may be perfectly conforming**, and the finding is worded as a suggestion because that is all it can be. It is worth having anyway: a response the client cannot use is usually not what the server meant to send.

**A 406 response is never reported** — that status is the server taking the other branch of the same choice.

**Weights:** a member with `q=0` is a refusal and does not count as accepting anything. `q` is read wherever it appears in the member and its name is matched case-insensitively, which is what §12.5.1 tells recipients to do. A `q` whose value is not a `qvalue` (`q=-1`, `q=0.0001`, `q=1e-9`) is not a weight at all; the member keeps the default weight of 1, and reporting the malformed value is `message_accept_header_media_type_syntax`'s job.

**Nothing is reported when the question has no answer.** If no member of `Accept` is a `media-range` — `Accept: *`, `Accept: not-a-media-range`, an empty value — then no preference was expressed that this rule can read, and naming the response for a defect in the request would be the wrong finding about the wrong message. Likewise if the response carries more than one `Content-Type` field line: recipients differ over which one they act on, so which media type the client actually got is unknown.

**Quoting that never closes is declined too.** After a stray `"` no separator can be trusted — the rest of the field collapses into one member — so `Accept: text/html;foo="x, application/json` is not reported against an `application/json` response it plainly asks for.

**Known leniency: media-range parameters are ignored.** §12.5.1 lets a range carry media type parameters and makes a more specific range take precedence, so `text/plain;format=flowed` and `text/plain;format=fixed` are different preferences. This rule compares only type and subtype, which can only make it quieter — a response whose *parameters* nobody asked for goes unmentioned.

## Specifications

- [RFC 9110 §12.4.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.4.1): Absence: what a missing negotiation field means, and — the reason this rule is advisory — the origin server's explicit choice between sending 406 and disregarding the header entirely
- [RFC 9110 §12.5.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.1): Accept: the `#( media-range [ weight ] )` list, the three shapes a `media-range` takes and what the asterisk ranges over, the instruction to find `q` wherever it sits, and the media-range parameters this rule does not compare
- [RFC 9110 §12.4.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.4.2): Quality Values: `qvalue`, the meaning of a zero weight, and the default weight of 1 that a member with no readable `q` keeps
- [RFC 9110 §12.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.1): Proactive negotiation: that a user agent cannot rely on its preferences being honoured, which is the same point as §12.4.1's from the client's side
- [RFC 9110 §15.5.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.7): 406 (Not Acceptable): the status this rule suggests, and the one response it never reports
- [RFC 9110 §8.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3): Content-Type: that recipients differ over which member of a duplicated field they act on, which is why a response with two Content-Type lines is not judged

## Configuration

```toml
[rules.message_accept_and_content_type_negotiation]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
GET /resource HTTP/1.1
Accept: application/json

HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
```

### ✅ Good (a range covers every subtype of its type)

```http
GET /resource HTTP/1.1
Accept: text/*

HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
```

### ✅ Good (the server honoured the header instead of disregarding it)

```http
GET /resource HTTP/1.1
Accept: application/json

HTTP/1.1 406 Not Acceptable
Content-Type: text/html; charset=utf-8
```

### ❌ Bad

```http
GET /resource HTTP/1.1
Accept: application/json

HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
```

### ❌ Bad (a weight of zero is a refusal)

```http
GET /resource HTTP/1.1
Accept: text/html;q=0

HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
```
