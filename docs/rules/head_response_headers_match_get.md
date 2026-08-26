<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# HEAD response headers match GET

## Description

Ensure responses to `HEAD` carry the header fields the server would have sent for a `GET` on the same resource. RFC 9110 §9.3.2 asks this with a SHOULD, and the configured `headers` array names the fields to compare; `Content-Length` is the exception, governed by §8.6's MUST NOT unless its value equals the octet count a `GET` would have delivered.

**The comparison is evidence, not the sentence.** §9.3.2 is about the response the server *would have sent* for a `GET` at that moment, and what this rule has is a `GET` it observed earlier. It therefore declines whenever the two responses say they describe different things — a different status code, or a different `ETag` or `Last-Modified`. What it cannot see is a representation that changed with no validator to show it, so every finding assumes the resource held still between the two exchanges.

**The exceptions are an open class.** §9.3.2 permits a server to omit any header field whose value is determined only while generating the content, and no field announces its membership — so the rule can only excuse the ones a specification names: `Content-Length` (§8.6), `Vary` (§9.3.2's own example) and `Transfer-Encoding` (RFC 9112 §6.1, which also makes its value incomparable). A field outside that set which the server legitimately omitted is still reported; configure `headers` accordingly.

## Specifications

- [RFC 9110 §9.3.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.2): The rule's sentence, quoted whole: "The server SHOULD send the same header fields in response to a HEAD request as it would have sent if the request method had been GET. However, a server MAY omit header fields for which a value is determined only while generating the content." The MAY names a class, and the section prints Content-Length and Vary as examples of it rather than as its membership
- [RFC 9110 §8.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6): Content-Length is the one requirement here that is not a SHOULD: "a server MUST NOT send Content-Length in such a response unless its field value equals the decimal number of octets that would have been sent in the content of a response if the same request had used the GET method". The same sentence opens with the MAY that lets a HEAD response omit it
- [RFC 9110 §8.8](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8): Why a difference between the two responses is not automatically a finding: validator fields "describe the selected representation chosen by the origin server while handling the response", so an ETag or Last-Modified that moved between the observed GET and this HEAD says the resource changed, and the rule declines
- [RFC 9112 §6.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.1): Transfer-Encoding is excluded outright: it "MAY be sent in a response to a HEAD request", the indication "is not required", and any recipient on the response chain "can remove transfer codings when they are not needed" — so neither its presence nor its value is comparable across the two messages

## Configuration

```toml
[rules.head_response_headers_match_get]
enabled = true
severity = "warn"
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

### ❌ Bad (§8.6: a Content-Length that is not the octet count a GET would have delivered)

```http
GET /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 100

HEAD /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 50
```
