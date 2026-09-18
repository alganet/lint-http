<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# HEAD response headers match GET

## Description

Ensure responses to `HEAD` carry the header fields the server would have sent for a `GET` on the same resource. RFC 9110 §9.3.2 asks this with a SHOULD, and the configured `headers` array names the fields to compare; `Content-Length` is the exception, governed by §8.6's MUST NOT unless its value equals the octet count a `GET` would have delivered.

**The comparison is evidence, not the sentence.** §9.3.2 is about the response the server *would have sent* for a `GET` at that moment, and what this rule has is the `GET`s it observed earlier. It reads all of them, and a `GET` counts only where it describes the same thing the `HEAD` does — the same status code, no `ETag` or `Last-Modified` that moved, and a request that selects the same representation under the response's `Vary` (RFC 9111 §4.1) — and then, field by field, only where every `GET` that counts gives the same answer. Two `GET`s that already disagree about a length are a resource that is not holding still, and a `HEAD` matching either of them or neither shows nothing about the server, so that field is not reported. What the rule cannot see is a representation that changed with no validator to show it and no second `GET` to disagree, so every finding assumes the resource held still between the exchanges it read. Where the `GET`'s own reading did not reach the end of its body, the octets it was counted for measure the reading and not the representation, and the `Content-Length` comparison declines rather than convict the later `HEAD` of an earlier client's disconnect.

**The exceptions are an open class.** §9.3.2 permits a server to omit any header field whose value is determined only while generating the content, and no field announces its membership — so the rule can only excuse the ones a specification names: `Content-Length` (§8.6), `Vary` (§9.3.2's own example) and `Transfer-Encoding` (RFC 9112 §6.1, which also makes its value incomparable). A field outside that set which the server legitimately omitted is still reported; configure `headers` accordingly.

## Violations

- [method_head_conflicting](../violations/method_head_conflicting.md) — A HEAD response disagrees with the GET it stands in for
- [method_head_content_length_ambiguous](../violations/method_head_content_length_ambiguous.md) — A HEAD and a GET report different lengths for a resource nothing pins
- [method_head_content_length_conflicting](../violations/method_head_content_length_conflicting.md) — A HEAD response states a length the GET would not have sent

## Specifications

- [RFC 9110 §9.3.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.2): HEAD — the SHOULD to send the same header fields a GET would have carried, the MAY that excuses fields whose value is determined only while generating the content, and GET's content paragraph repeated word for word
- [RFC 9110 §8.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6): Content-Length is the one requirement about a HEAD response that is not a SHOULD: "a server MUST NOT send Content-Length in such a response unless its field value equals the decimal number of octets that would have been sent in the content of a response if the same request had used the GET method". The same sentence opens with the MAY that lets a HEAD response omit it
- [RFC 9110 §8.8](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8): Why a difference between the two responses is not automatically a finding: validator fields "describe the selected representation chosen by the origin server while handling the response", so an ETag or Last-Modified that moved between the observed GET and this HEAD says the resource changed, and the rule declines
- [RFC 9111 §4.1](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.1): Which observed GET is the same request: a response that varies names the request fields that selected it, and a GET whose request differs from the HEAD's in any of them was answered about another representation, so it is no yardstick for this one
- [RFC 9112 §6.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.1): Transfer-Encoding is excluded outright: it "MAY be sent in a response to a HEAD request", the indication "is not required", and any recipient on the response chain "can remove transfer codings when they are not needed" — so neither its presence nor its value is comparable across the two messages

## Configuration

```toml
[rules.head_response_headers_match_get]
enabled = true
headers = ["etag", "content-type", "content-length"]
```

## Examples

### ✅ Good (the HEAD carries the fields the GET carried)

```http
GET /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
ETag: "v2"
Content-Type: text/plain
Content-Length: 42

HEAD /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
ETag: "v2"
Content-Type: text/plain
Content-Length: 42
```

### ✅ Good (§9.3.2's own example: a value determined while generating the content need not be generated for a HEAD)

```http
GET /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
ETag: "v2"
Content-Type: text/plain
Content-Length: 42
Vary: Accept-Encoding

HEAD /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
ETag: "v2"
Content-Type: text/plain
```

### ✅ Good (the representation changed between the two exchanges, and the entity tags say so)

```http
GET /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
ETag: "v1"
Content-Type: text/plain

HEAD /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
ETag: "v2"
Content-Type: text/html
```

### ✅ Good (two GETs had already disagreed about the length, so the resource is not holding still and the HEAD is measured against neither)

```http
GET /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 1951131

GET /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 1951116

HEAD /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 1951131
```

### ✅ Good (RFC 9111 §4.1: the GET asked for gzip and was answered under Vary: Accept-Encoding, so its length belongs to a representation the HEAD did not select)

```http
GET /resource HTTP/1.1
Host: example.com
Accept-Encoding: gzip

HTTP/1.1 200 OK
Content-Type: text/html
Content-Encoding: gzip
Vary: Accept-Encoding
Content-Length: 234714

HEAD /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Type: text/html
Vary: Accept-Encoding
Content-Length: 1004024
```

### ❌ Bad (the HEAD omits a field the GET sent)

```http
GET /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
ETag: "v2"
Content-Type: text/plain

HEAD /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Type: text/plain
```

### ❌ Bad (§8.6: a Content-Length that is not the octet count a GET would have delivered, and one entity tag across both exchanges to say the representation held still)

```http
GET /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
ETag: "v2"
Content-Type: text/plain
Content-Length: 100

HEAD /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
ETag: "v2"
Content-Type: text/plain
Content-Length: 50
```

### ❌ Bad (§8.6: a HEAD declaring zero octets for a resource the GET delivered content for, which no validator is needed to read)

```http
GET /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 73091

HEAD /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 0
```

### ❌ Bad (the counts differ and neither response carries a validator, so a misstated length and a resource that changed are the same observation)

```http
GET /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 1004101

HEAD /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 1004024
```
