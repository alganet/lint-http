<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Client Request Version Method Validity

## Description

Reports a request that carries content under a method whose definition gives content no meaning there. RFC 9110 says it about GET (§9.3.1), HEAD (§9.3.2) and DELETE (§9.3.5) in three identical paragraphs: content in such a request "has no generally defined semantics, cannot alter the meaning or target of the request, and might lead some implementations to reject the request and close the connection because of its potential as a request smuggling attack". CONNECT (§9.3.6) is stated differently and reported differently — see below.

**A SHOULD NOT with a condition this rule cannot check.** The GET/HEAD/DELETE sentences end "unless it is made directly to an origin server that has previously indicated, in or out of band, that such a request has a purpose and will be adequately supported". An agreement reached out of band leaves no trace in the message, so a request under such an agreement is reported like any other. The exemption is not simply ignored, though: the next sentence in each of those three paragraphs says "An origin server SHOULD NOT rely on private agreements to receive content, since participants in HTTP communication are often unaware of intermediaries along the request chain" — and a request this tool observed at a proxy has, by construction, an intermediary in its chain.

**CONNECT is a different kind of finding.** §9.3.6 states "A CONNECT request message does not have content." — a definition, not a modal a sender disobeys. So the report is that the message contradicts its own method's definition. It is also the one method judged on its header section alone: §9.3.6 says "The interpretation of data sent after the header section of the CONNECT request message is specific to the version of HTTP in use", so a per-transaction octet count carries no version-independent claim that those octets are content — and where the CONNECT succeeded they are the tunnel's own traffic.

**Content, not framing.** Each of the three paragraphs opens "Although request message framing is independent of the method used", so a `Transfer-Encoding` is not by itself content: a chunked request whose first chunk is the terminator carries none, and over HTTP/2 and HTTP/3 content arrives with no framing field at all. Where a body was captured, its octet count is what decides; otherwise the request's own `Content-Length` is.

**Not checked here.** TRACE's §9.3.8 MUST NOT is `semantic_trace_method_echo`'s, so enabling this rule alone leaves TRACE unreported. OPTIONS may carry content (§9.3.7), which comes with a MUST on the `Content-Type` describing it that this rule does not check. Neither does any other method: a method this specification does not define has no content semantics to contradict. And nothing here reads `tx.request.version`, despite the id.

## Specifications

- [RFC 9110 §9.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.1): Methods overview — the method token is case-sensitive, which is why the four names below are matched exactly and a lowercase `get` is not a GET
- [RFC 9110 §9.3.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.1): GET — the SHOULD NOT, its `unless` clause, and the sentence that declines to rely on the private agreement the clause describes. Also the statement that framing is independent of the method, which is why a Transfer-Encoding alone is not content
- [RFC 9110 §9.3.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.2): HEAD — the same paragraph, word for word
- [RFC 9110 §9.3.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.5): DELETE — the same paragraph again
- [RFC 9110 §9.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6): CONNECT — a definition rather than a modal, and the sentence that makes the octets after the header section tunnel payload instead of content
- [RFC 9110 §8.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6): Content-Length as the amount of data enclosed — the fallback evidence when no body was captured

## Configuration

```toml
[rules.client_request_version_method_validity]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
POST /upload HTTP/1.1
Host: example.com
Content-Length: 123

<binary data>
```

### ✅ Good (DELETE with no body)

```http
DELETE /resource/42 HTTP/1.1
Host: example.com
```

### ❌ Bad (GET with a body)

```http
GET /search HTTP/1.1
Host: example.com
Content-Length: 5

hello
```

### ❌ Bad (CONNECT declaring content)

```http
CONNECT server.example.com:443 HTTP/1.1
Host: server.example.com:443
Content-Length: 1

x
```
