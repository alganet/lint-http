<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# The header fields a 206 owes the 200 it is a part of

## Description

RFC 9110 §15.3.7 says a server generating a `206 (Partial Content)` **MUST** generate `Date`, `Cache-Control`, `ETag`, `Expires`, `Content-Location` and `Vary` *"if the field would have been sent in a 200 (OK) response to the same request"*. This rule reads that sentence.

**It had been quoted only to say what it does not require.** The list is the reason `Accept-Ranges` is not owed on a 206, and that is what every rule reaching for §15.3.7 reached for; whether the six named fields themselves arrived was asked by nothing.

**The requirement is conditional, and the condition is not in the 206.** A response that omits `Vary` violates nothing unless the `200` it is a part of would have carried one, and no single message says what that hypothetical `200` holds. So this rule answers it with an observation instead: an earlier `200`, from the same client, for the same resource, answering **the same request** — same method, same target URI, and the same header fields but for the `Range` that asked for the part. Where no such exchange was seen, nothing is reported.

**"The same request" is read strictly.** Every request header field but `Range` and `If-Range` has to match, octet for octet. The fields at issue are the ones content negotiation moves — `Vary` is a statement about which request fields select the representation — so a looser comparison would be reasoning about a `200` the server never had occasion to send. What that costs is silence wherever a client changed anything else between the two requests, and silence is the right direction to be wrong in for a finding that ships at `error`.

**One finding per field**, each naming the field and the value the `200` sent, so an operator has the line to put back rather than a list to check.

**What the omission costs.** §15.3.7 makes a 206 heuristically cacheable and RFC 9111 §3.3 lets a cache store its content, so a partial response whose `Vary` went missing is one the cache has nothing to key on — and it will be handed to a request whose `Accept-Encoding` selects a different representation. For the other five the loss is the client's: it is assembling a representation from parts, and a field the whole would have carried is one it never receives.

**Not the subsections' fields.** Whether a single-part 206 carries a `Content-Range`, and whether a multipart one carries the `multipart/byteranges` `Content-Type`, are §15.3.7.1's and §15.3.7.2's requirements and `range_and_content_range_consistent` reads them. This rule reads the six the parent section names, which is the set whose condition is a `200` nobody sent.

**The 304 twin.** `status_304_required_fields` reads §15.4.5's identical sentence about the other status code that stands in for a `200`, over the same six fields. The two differ only in which request field is allowed to differ between the exchanges — a precondition there, a `Range` here.

## Violations

- [status_206_field_missing](../violations/status_206_field_missing.md) — A 206 omits a header field the 200 it is a part of carried

## Specifications

- [RFC 9110 §15.3.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.7): 206 Partial Content: the status code is a range request being fulfilled, and a single-part 206 MUST carry a `Content-Range` describing the enclosed range
- [RFC 9111 §3.3](https://www.rfc-editor.org/rfc/rfc9111.html#section-3.3): Storing Incomplete Responses — a cache may store the content of a 206 and later combine the parts, which is what makes a `Vary` dropped from one of them a stored response nothing tells the cache to key

## Configuration

```toml
[rules.status_206_required_fields]
enabled = true
```

## Examples

### ✅ Good — the 206 repeats every listed field the 200 carried

```http
GET /a HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Date: Mon, 01 Jan 2024 00:00:00 GMT
ETag: "abc"
Vary: Accept-Encoding
Content-Length: 1024

GET /a HTTP/1.1
Host: example.com
Range: bytes=0-9

HTTP/1.1 206 Partial Content
Date: Mon, 01 Jan 2024 00:00:01 GMT
ETag: "abc"
Vary: Accept-Encoding
Content-Range: bytes 0-9/1024
```

### ✅ Good — a field the 200 did not send either is not one the 206 owes

```http
GET /a HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Date: Mon, 01 Jan 2024 00:00:00 GMT
ETag: "abc"

GET /a HTTP/1.1
Host: example.com
Range: bytes=0-9

HTTP/1.1 206 Partial Content
Date: Mon, 01 Jan 2024 00:00:01 GMT
ETag: "abc"
Content-Range: bytes 0-9/1024
```

### ❌ Bad — the negotiation the 200 announced, dropped from the part, so a cache storing it has nothing to key on

```http
GET /a HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Date: Mon, 01 Jan 2024 00:00:00 GMT
ETag: "abc"
Vary: Accept-Encoding

GET /a HTTP/1.1
Host: example.com
Range: bytes=0-9

HTTP/1.1 206 Partial Content
Date: Mon, 01 Jan 2024 00:00:01 GMT
ETag: "abc"
Content-Range: bytes 0-9/1024
```

### ❌ Bad — the freshness the 200 stated, absent from the part

```http
GET /a HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Date: Mon, 01 Jan 2024 00:00:00 GMT
ETag: "abc"
Cache-Control: max-age=60

GET /a HTTP/1.1
Host: example.com
Range: bytes=0-9

HTTP/1.1 206 Partial Content
Date: Mon, 01 Jan 2024 00:00:01 GMT
ETag: "abc"
Content-Range: bytes 0-9/1024
```
