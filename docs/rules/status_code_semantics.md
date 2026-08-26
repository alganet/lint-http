<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Challenges the 401 and the 407 are defined by

## Description

Two status codes are defined in terms of a field the response has to carry, and this rule reports the responses that do not carry it — plus, advisorily, a `Proxy-Authenticate` arriving on any other status.

- `401 Unauthorized` — a server generating one **MUST** send a `WWW-Authenticate` header field containing at least one challenge applicable to the target resource (RFC 9110 §15.5.2, §11.6.1)
- `407 Proxy Authentication Required` — the proxy generating one **MUST** send at least one `Proxy-Authenticate` header field, containing a challenge applicable to that proxy for the request (RFC 9110 §15.5.8, §11.7.1)

Both MUSTs ask for a **challenge**, not for a field line, so a `401` carrying an empty `WWW-Authenticate:` is reported too. That case is not a syntax defect: both fields are defined as `#challenge`, a `#` list is permitted to hold no elements at all, and a recipient is required to accept the empty ones it does hold — so the value is well-formed, and what it fails is its status definition. Whether an element that *is* present is a well-formed challenge belongs to `message_www_authenticate_challenge_syntax`; this rule only asks whether one is there at all.

**A `WWW-Authenticate` on any other status is not reported.** §11.6.1 says a server **MAY** generate one in other responses, to indicate that supplying credentials (or different credentials) might affect the response — so the field is permitted anywhere and a rule reporting it would be reporting a permission being used.

**A `Proxy-Authenticate` outside a 407 is reported, and no requirement is violated by such a response.** §11.7.1 gives that field no matching permission, but it states no prohibition either; what it does say is that the field addresses the one client that chose this proxy, and outside a 407 nothing tells that client what to do with the challenge. The finding is advisory — configure the severity accordingly. The two fields are treated differently here on purpose, and the difference is one sentence in §11.6.1 that §11.7.1 does not have.

The response status and those two fields are the whole input — whether a challenge is there, never what it says. A 401 is measured from the response as it arrived rather than as it was generated, which §11.6.1 makes the same question by forbidding an intermediary from modifying the field; for the 407 no such sentence exists, and §11.7.1 addresses that field to a single hop, so an absence there is weaker evidence about the proxy that generated the status. The rule says nothing about `Authorization`, `Proxy-Authorization`, or the content of the response.

## Specifications

- [RFC 9110 §15.5.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.2): 401 (Unauthorized) — the MUST for a `WWW-Authenticate` header field containing at least one challenge
- [RFC 9110 §11.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.6.1): `WWW-Authenticate` — the field definition, the same MUST for a 401, and the MAY that permits the field on any other response (which is why this rule reports no such response)
- [RFC 9110 §15.5.8](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.8): 407 (Proxy Authentication Required) — the MUST for a `Proxy-Authenticate` header field containing a challenge applicable to that proxy
- [RFC 9110 §11.7.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.7.1): `Proxy-Authenticate` — at least one field in each 407 the proxy generates, and the sentence limiting the field to the next outbound client, which is all that stands behind the advisory finding on other statuses
- [RFC 9110 §5.6.1.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.2): Empty list elements do not contribute to the count of elements present — why `WWW-Authenticate: ,` carries no challenge
- [RFC 9110 §15](https://www.rfc-editor.org/rfc/rfc9110.html#section-15): Status Codes — the part of the document both status definitions live in

## Configuration

```toml
[rules.status_code_semantics]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="example"

{"error":"unauthorized"}
```

```http
HTTP/1.1 407 Proxy Authentication Required
Proxy-Authenticate: Basic realm="proxy"
```

### ✅ Good — a server MAY hint that credentials would change the answer

```http
HTTP/1.1 200 OK
WWW-Authenticate: Basic realm="example"

{"ok":true}
```

### ❌ Bad

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{"error":"unauthorized"}
```

### ❌ Bad — the field line is there and the challenge is not

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate:
```

### ❌ Bad

```http
HTTP/1.1 407 Proxy Authentication Required
Content-Type: text/plain
```

### ❌ Bad — advisory: no requirement is violated by this response

```http
HTTP/1.1 200 OK
Proxy-Authenticate: Basic realm="proxy"
```
