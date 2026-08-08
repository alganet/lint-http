<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server 200 Vs 204 Body Consistency

## Description

Reports a `200 (OK)` response that carries no content, so an operator can check whether `204 (No Content)` was meant instead. **Nothing is being violated.** RFC 9110 §15.3.1 says an origin server *"ought to"* send a 204 *"if some aspect of the request indicates a preference for no content upon success"* — a modal weaker than SHOULD, and a condition about the *request* that no field on the wire records, so this rule cannot tell the case the sentence is about from the case it is not. It reports both. The same section's preceding sentence expects a 200 to contain content *"unless the message framing explicitly indicates that the content has zero length"*, which is the very state reported here, and §6.4.1 says of every response that is not a HEAD response, a CONNECT tunnel, a 1xx, a 204 or a 304: *"All other responses do include content, although that content might be of zero length."* A 200 returning an empty representation — an empty file, an empty collection — is therefore conforming, and reads as a finding only because the alternative status code is often the better answer. Two responses are exempt because they cannot carry content at all: responses to `HEAD` (§9.3.2) and 2xx responses to `CONNECT`, where the tunnel begins where the content would be and a 204 would not open it. Method tokens are compared case-sensitively (§9.1). Emptiness is read from the declared `Content-Length` when the response has no `Transfer-Encoding`, and otherwise from the captured content length; when neither is available the response is not reported, and an invalid `Content-Length` is left to `message_content_length`.

## Specifications

- [RFC 9110 §15.3.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.1): 200 (OK) — the whole basis of this rule, and both of its sentences matter: a 200 is expected to contain content "unless the message framing explicitly indicates that the content has zero length" (the reported state is that exception, not a breach), and the 204 advice is an "ought to" conditioned on the request preferring no content, which is not observable. The same paragraph excludes CONNECT
- [RFC 9110 §15.3.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.5): 204 (No Content) — the alternative the advice names: success, no content, and terminated by the end of the header section
- [RFC 9110 §6.4.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.4.1): Content Semantics — which responses have no content (HEAD, 2xx to CONNECT, 1xx, 204, 304) and, for every other response, that its content "might be of zero length": a zero-length 200 is contemplated by the specification
- [RFC 9110 §9.3.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.2): HEAD — "the server MUST NOT send content in the response", so an empty response to HEAD says nothing about what the server intended
- [RFC 9110 §9.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6): CONNECT — a 2xx switches the connection to tunnel mode immediately after the header section; 204 is not an alternative there
- [RFC 9112 §6.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.3): Message body length — a Transfer-Encoding overrides a Content-Length, so the declared length is read only in its absence; the captured content length is still consulted

## Configuration

```toml
[rules.server_200_vs_204_body_consistency]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 24

{"status":"ok","data":1}
```

### ✅ Good (HEAD request)

```http
HEAD /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Date: Mon, 01 Jan 2024 00:00:00 GMT
```

### ✅ Good (CONNECT tunnel — the content is where the tunnel starts)

```http
CONNECT server.example.com:443 HTTP/1.1
Host: server.example.com:443

HTTP/1.1 200 OK
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Content-Length: 0
```
