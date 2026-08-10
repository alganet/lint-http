<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Semantic TRACE Method Echo

## Description

Reports a TRACE request that carries content, and a TRACE request that carries one of the fields RFC 9110 §9.3.8 names when it forbids handing sensitive data to a loop-back. A TRACE asks the final recipient to "reflect the message received, excluding some fields described below, back to the client as the content of a 200 (OK) response", so what a TRACE request contains is what a TRACE response discloses.

**Content.** §9.3.8: "A client MUST NOT send content in a TRACE request." Content is §6.4's — the stream of octets after the header section, counted once framing has been taken off — so a `Transfer-Encoding: chunked` is not by itself content, a chunked TRACE whose only chunk is the terminator carries none, and over HTTP/2 and HTTP/3 content arrives with no framing field at all. Where a body was captured its octet count decides; otherwise the request's own `Content-Length` does.

**Sensitive fields.** §9.3.8 also says "A client MUST NOT generate fields in a TRACE request containing sensitive data that might be disclosed by the response." Whether a value is sensitive is not something a message states, so this rule reports exactly the two kinds of data the section names as its example — stored user credentials (`Authorization`, `Proxy-Authorization`) and cookies (`Cookie`). Sensitive data under any other field name is not reported, and cannot be: the sentence leaves the class open on purpose.

**Not checked: the response's media type.** RFC 7231 §4.3.8 required `message/http` on a TRACE response; RFC 9110 does not. §9.3.8 now calls that format one way to do so, and Appendix B.3 records the change — "The normative requirement to use the "message/http" media type in TRACE responses has been removed." A TRACE response in another media type is reported by nothing here. A response that carries content with no `Content-Type` at all is `server_content_type_present`'s finding.

**Not checked: whether the response reflected the request.** The reflection is a SHOULD addressed to "the final recipient" — the origin server, or the first server to receive a `Max-Forwards` of zero — and no field of a message says which recipient answered it.

## Specifications

- [RFC 9110 §9.3.8](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.8): TRACE — the two client `MUST NOT`s this rule reports, the example naming credentials and cookies, and the `SHOULD` to reflect the message, which is addressed to a recipient no message identifies
- [RFC 9110 §9.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.1): The method token is case-sensitive, which is why `TRACE` is matched exactly and a lowercase `trace` is not a TRACE
- [RFC 9110 §6.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.4): Content — the octet stream left after framing is removed, which is what the content check measures instead of the presence of a framing field
- [RFC 9110 §11.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.6.2): `Authorization` carries the user agent's credentials; §11.7.2 says the same of `Proxy-Authorization` for a proxy
- [RFC 6265 §4.2.1](https://www.rfc-editor.org/rfc/rfc6265.html#section-4.2.1): `Cookie` is the field a user agent returns stored cookies in — the second kind of data §9.3.8's example names
- [RFC 9110 §B.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-B.3): Changes from RFC 7231 — the normative requirement to use `message/http` in TRACE responses was removed, which is why this rule no longer asks for it

## Configuration

```toml
[rules.semantic_trace_method_echo]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good A loop-back carrying nothing to reflect

```http
TRACE /diagnostics HTTP/1.1
Host: example.com
Max-Forwards: 3
```

### ❌ Bad Content in a TRACE request

```http
TRACE /diagnostics HTTP/1.1
Host: example.com
Content-Length: 4

ping
```

### ❌ Bad Credentials and cookies, which the reflection would echo back

```http
TRACE /diagnostics HTTP/1.1
Host: example.com
Authorization: Basic dXNlcjpwYXNzd29yZA==
Cookie: session=8f1c2b
```
