<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# A 201 that does not say what it created

## Description

RFC 9110 §9.3.3 asks an origin server that has created one or more resources while processing a `POST` request to send a `201 Created` response containing a `Location` header field that provides an identifier for the primary resource created. This rule reports a `201` answering a `POST` that carries no `Location`.

**The status is the evidence for the SHOULD's condition.** The sentence opens *"If one or more resources has been created on the origin server"*, which nothing in a message states directly — but §15.3.2 defines the `201` as indicating exactly that, so a server that chose the status has already asserted the condition holds. No other status is read: a `200` or a `204` answering a `POST` asserts no creation, and §9.3.3 asks nothing of it.

**Nothing is malformed without the field.** §15.3.2 says the primary resource created is identified *"by either a Location header field in the response or, if no Location header field is received, by the target URI"* — so a `201` with no `Location` does name the created resource, just not explicitly. The finding is that the identifier is left to be inferred, which is what the SHOULD buys.

**The finding names the request-target, not the target URI.** The two are the same string only when the request-target is in absolute-form (RFC 9112 §3.3). Over HTTP/1.1 it arrives in origin-form, where it is the target URI's combined path and query and nothing more — the authority comes from `Host` and the scheme from whether the connection was secured, which no part of the message records. So the message prints what the request addressed and leaves the reconstruction to the reader who knows the connection.

**The sentence is addressed to the origin server.** A capture taken between a client and a proxy cannot tell an origin server's `201` from one a gateway produced on its behalf, and nothing on the wire records which component chose the status. Read the finding as being about whichever one did.

**Only presence is read.** Field names are case-insensitive (§5.1), so the field is found however it was written, and a value that cannot be decoded still counts as present — the message on the wire carries the field. Whether the value is a usable `URI-reference`, whether it is empty, and whether several field lines were sent are `server_location_header_uri_valid`'s questions. A `Location` in a trailer section is not counted: §6.5.1 permits a trailer field only where the field's own definition permits it, and §10.2.2 does not — so a `201` that writes its `Location` after the content is reported here for not carrying one, and by `message_trailer_fields_validity` for the `MUST NOT` it broke getting there.

**Not reported: a `Location` on a `POST` response that is not a `201`.** This rule previously reported every other 2xx carrying the field, advising the sender to "use 201 Created when a new resource is created" — a claim about what the sender did that no sentence licenses, and one §10.2.2 declines to make by leaving the field's relationship to the response to *"the combination of request method and status code semantics"*. `server_redirect_status_and_location_validity` owns that finding, reports it as advice, and reports it on every status rather than only on the 2xx ones; its description names the `202 Accepted` carrying a status-monitor `Location` as the case that shows why it is advice and not a violation.

**Not reported: a `PUT` that created a resource.** §9.3.4 requires the `201` there with a MUST and asks nothing about `Location`, because the target URI of a `PUT` is already the identifier of what it creates. The method is compared exactly, since §9.1 says the method token is case-sensitive: a request whose method is `post` is not a `POST` request, and `client_request_method_token_valid` is the rule that reports it.

## Specifications

- [RFC 9110 §9.3.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.3): POST: the SHOULD this rule enforces — an origin server that created one or more resources sends a 201 containing a Location field that provides an identifier for the primary resource created
- [RFC 9110 §15.3.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.2): 201 Created: the status indicates one or more new resources were created, which is what makes §9.3.3's condition observable, and the primary resource is identified by the Location field or, if none is received, by the target URI
- [RFC 9110 §10.2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.2): Location: on a 201 (Created) response the value refers to the primary resource created by the request. The field's relationship to any other status is left to "the combination of request method and status code semantics", which is why a Location on a non-201 is not reported here
- [RFC 9110 §9.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.1): The method token is case-sensitive, which is why `POST` is matched exactly and a lowercase `post` is not a POST

## Configuration

```toml
[rules.semantic_post_creates_resource]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
POST /widgets HTTP/1.1
Host: example.com
Content-Type: application/json
Content-Length: 17

{"name":"fidget"}

HTTP/1.1 201 Created
Location: /widgets/123
Content-Type: application/json

{"id":123}
```

### ✅ Good (no creation is claimed, so §9.3.3 asks for nothing)

```http
POST /widgets HTTP/1.1
Host: example.com
Content-Type: application/json
Content-Length: 17

{"name":"fidget"}

HTTP/1.1 200 OK
Content-Type: application/json

{"status":"ok"}
```

### ❌ Bad (the created resource is identified by the target URI, but not stated)

```http
POST /widgets HTTP/1.1
Host: example.com
Content-Type: application/json
Content-Length: 17

{"name":"fidget"}

HTTP/1.1 201 Created
Content-Type: application/json

{"id":123}
```
