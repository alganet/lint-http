<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Patch Partial Update

## Description

Reports a `PATCH` request that carries content without a `Content-Type` naming the patch document format.

**Why the field is load-bearing here.** A `PATCH` request's content is not a new representation of the resource — it is a set of instructions for changing one, and RFC 5789 §2 says that set "is represented in a format called a *patch document* identified by a media type". The media type is what tells the server which instructions it is holding, which is why §2 can require that "[s]ervers MUST ensure that a received patch document is appropriate for the type of resource identified by the Request-URI" and why §2.2 offers `415 (Unsupported Media Type)` — permissively, "can be specified" — for one it does not support.

**This is a SHOULD, and it has a stated exception.** The requirement is RFC 9110 §8.3's: a sender generating a message containing content "SHOULD generate a Content-Type header field in that message *unless the intended media type of the enclosed representation is unknown to the sender*". Nothing on the wire separates a sender that did not know from one that did not bother — but a client that built a patch document chose its format, so the exception is at its least plausible on this method. Without the field, §8.3 leaves the recipient two ways to proceed: assume `application/octet-stream`, or sniff the data.

**The value is not judged.** A media type does not have to be *named* like a patch format to be one: RFC 5789's own examples are `application/example` and `text/example`, and §2 says outright that "there is no single default patch document format that implementations are required to support". There is no registry of patch formats and no naming convention, so nothing in a lone request says whether the type is one. What a particular server accepts is *discovered*, from the `Accept-Patch` it advertises (RFC 5789 §3.1) — `patch_method_content_type_match` is the rule that compares a request against it. This rule previously reported any media type whose type or subtype did not contain the string `patch`, which reported RFC 5789's own example.

**Content, not framing.** The condition is that the message *contains content*, so the captured octet count decides it; a `Transfer-Encoding` is how octets were delimited, not evidence that there were any, and a chunked request whose only chunk is the terminator carries none. Only where nothing was captured does the rule fall back to the sender's declared `Content-Length`.

**The method is compared exactly**, because RFC 9110 §9.1 says the method token is case-sensitive: a request whose method is `patch` is not a `PATCH` request, and `request_method_token_valid` is the rule that reports the spelling. A `Content-Type` whose octets are not visible ASCII counts as present here; `content_type_valid` reports what is wrong with it.

## Specifications

- [RFC 5789 §2](https://www.rfc-editor.org/rfc/rfc5789.html#section-2): The PATCH method — a patch document is identified by a media type, the request's fields describe that document rather than the resource, and no patch format is one implementations must support, which is why this rule reports the field's absence and does not judge its value
- [RFC 5789 §2.2](https://www.rfc-editor.org/rfc/rfc5789.html#section-2.2): Error Handling — `415 (Unsupported Media Type)` is offered, not required, for a patch format the server does not support; it is the recipient's side of the media type this rule asks for
- [RFC 5789 §3.1](https://www.rfc-editor.org/rfc/rfc5789.html#section-3.1): The `Accept-Patch` header — how a server says which patch formats it takes. It is a response field, so a lone request cannot be measured against it; `patch_method_content_type_match` is the rule that has one
- [RFC 9110 §8.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3): Content-Type — the SHOULD this rule enforces, the exception excusing a sender that does not know its own media type, and the two guesses a recipient is left with when the field is absent
- [RFC 9110 §6.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.4): Content — the octet stream left once framing has been taken off, which is why a `Transfer-Encoding` is not evidence of any and the captured count decides
- [RFC 9110 §9.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.1): Methods overview — the method token is case-sensitive, which is why `PATCH` is matched exactly and a lowercase `patch` is not a PATCH request
- [RFC 9110 §12.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.3): Request content negotiation — names `Accept-Patch` as the way the acceptable PATCH content types are discovered, rather than inferred from a media type's spelling

## Configuration

```toml
[rules.patch_partial_update]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
PATCH /widgets/123 HTTP/1.1
Host: example.com
Content-Type: application/json-patch+json
Content-Length: 52

[ { "op": "replace", "path": "/qty", "value": 20 } ]
```

### ✅ Good — a patch format need not be *named* like one. RFC 5789 §2.1's own example, printed here as the document prints it: `[description of changes]` stands in for a patch document of the declared length

```http
PATCH /file.txt HTTP/1.1
Host: www.example.com
Content-Type: application/example
If-Match: "e0023aa4e"
Content-Length: 100

[description of changes]
```

### ✅ Good — no content, so there is no patch document to identify

```http
PATCH /widgets/123 HTTP/1.1
Host: example.com
```

### ❌ Bad — content with no `Content-Type`, leaving the server to guess the patch format

```http
PATCH /widgets/123 HTTP/1.1
Host: example.com
Content-Length: 5

hello
```
