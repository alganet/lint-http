<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Response 405 Allow

## Description

Reports two things about a `405 (Method Not Allowed)` response: that it carries no `Allow` header field, and that the `Allow` it does carry names the very method the status refuses.

**The requirement, and where the licence for every other response comes from.** RFC 9110 §15.5.6: "The origin server MUST generate an Allow header field in a 405 response containing a list of the target resource's currently supported methods." §10.2.1 states the same requirement with the clause the other lacks — "An origin server MUST generate an Allow header field in a 405 (Method Not Allowed) response and MAY do so in any other response" — which is why no other status is asked for the field here.

**An empty value is an answer, not an omission.** §10.2.1: "An empty Allow field value indicates that the resource allows no methods, which might occur in a 405 response if the resource has been temporarily disabled by configuration." The section names this response by name, so `Allow:` on a 405 satisfies the MUST, and a whitespace-only value is the same value (§5.5). Presence is the whole of the first finding: whether the members are `method` tokens is `message_allow_header_method_tokens`'s question, and the value is read as octets rather than through a UTF-8 decode, so a field carrying `obs-text` counts as a field that is there.

**The second finding is the clause after "containing".** The status says "the method received in the request-line is known by the origin server but not supported by the target resource" (§15.5.6), and the field "lists the set of methods advertised as supported by the target resource" (§10.2.1). A 405 answering `POST` whose `Allow` names `POST` says both at once about one resource at one instant — the shape a router or a preflight handler produces when it answers 405 with the resource's full method list. Methods are matched exactly, because §9.1 says "The method token is case-sensitive": a 405 answering `get` while advertising `GET` is two methods and not this finding. A request whose method is empty is compared against nothing, since `method = token` derives no empty string; `request_method_token_valid` reports that value.

**Not reported: which methods the list should have held.** §10.2.1: "The actual set of allowed methods is defined by the origin server at the time of each request", and §9.1 adds "However, the set of allowed methods can change dynamically" — so no captured message disagrees with an `Allow` list by holding a different one, and the only disagreement this rule can see is the one internal to a single exchange.

**Not reported: that a 405 refused `GET` or `HEAD` at all.** §9.1's "All general-purpose servers MUST support the methods GET and HEAD" is addressed to the server, and the same section leaves the resource its own answer: "Once defined, a standardized method ought to have the same semantics when applied to any resource, though each resource determines for itself whether those semantics are implemented or allowed." So a resource that answers `GET` with a 405 is not reported for the status — though a 405 refusing `GET` while advertising `GET` is the finding above, like any other method.

**Not reported: a 405 where §9.1 asks for a 501.** "An origin server that receives a request method that is unrecognized or not implemented SHOULD respond with the 501 (Not Implemented) status code", against 405 for one "that is recognized and implemented, but not allowed for the target resource". Telling those apart means knowing which method names exist, which is a registry question: `request_method_token_valid` carries the required `registered_methods` array that asks it, and making that array required here would silence this rule's MUST on every deployment that has not written one.

**A trailer does not answer it.** The requirement is on a header field, and §6.5.1 forbids a trailer field unless the field's own definition permits one, which §10.2.1 does not. A 405 carrying `Allow` only in its trailer section is reported here as carrying none, and the finding says the trailer was seen — which is the whole of what this rule says about that placement. Reporting the placement itself belongs to `message_trailer_fields_validity`, the rule that applies §6.5.1 to field names; its list does not name `allow` today, so nothing in the catalogue reports an `Allow` for being in a trailer section, and that is an open question there rather than one this rule answers from outside.

**Scope and version.** Every HTTP version is measured: §15.5.6 says the method was "received in the request-line", which only an HTTP/1.x message has, but the status code it defines is the version-independent document's and HTTP/2 and HTTP/3 carry the same method in a `:method` pseudo-header. The requirement's subject is an origin server and a capture holds whatever answered — §3.7 carries every origin-server requirement onto "the outbound communication of a gateway", so a reverse proxy's 405 is measured on the same terms. A forward proxy that generates a 405 of its own is not an origin server for that response and is measured anyway, because no field of a message records which party wrote it.

## Specifications

- [RFC 9110 §15.5.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.6): The status code and its MUST — including the clause after "containing", which asks the field to hold the methods the target resource supports and so contradicts a list naming the method this response refuses
- [RFC 9110 §10.2.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.1): The field: the same MUST worded with the MAY that licenses silence on every other response, the sentence giving an empty value a meaning in this exact response, and the set of allowed methods being the origin server's at the time of each request
- [RFC 9110 §9.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.1): The method token is case-sensitive, which is why the request's method is matched against the members exactly; also the 405-versus-501 division and the sentence leaving each resource to decide which methods it allows
- [RFC 9110 §3.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-3.7): Why a requirement addressed to an origin server is measured against whatever answered: every one of them applies to a gateway's outbound communication
- [RFC 9110 §5.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.5): A field value excludes the whitespace around it, which is why a value that is only whitespace is the empty value and answers the requirement — and why the value is read as octets rather than through a UTF-8 decode, since `obs-text` is an octet field content admits
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): The delimiter set that makes splitting this field on every comma exact: a `method` is a `token`, which admits no comma, and the field embeds no `quoted-string` for one to hide inside
- [RFC 9110 §6.5.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.5.1): Why an `Allow` in the trailer section does not answer this requirement — a trailer field needs its own definition's permission, and the field's definition gives none

## Configuration

```toml
[rules.server_response_405_allow]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good The field is there and lists methods the refused one is not among

```http
POST /resource HTTP/1.1
Host: example.com

HTTP/1.1 405 Method Not Allowed
Content-Type: text/plain
Allow: GET, HEAD
```

### ✅ Good §10.2.1's temporarily disabled resource — an empty value is what "no methods" looks like

```http
DELETE /resource HTTP/1.1
Host: example.com

HTTP/1.1 405 Method Not Allowed
Allow:
```

### ❌ Bad Two field lines in one section are one list, and the refused method is a member of it

```http
PUT /resource HTTP/1.1
Host: example.com

HTTP/1.1 405 Method Not Allowed
Allow: GET
Allow: PUT
```

### ✅ Good The method token is case-sensitive, so `get` and `GET` are two methods and the response contradicts nothing

```http
get /resource HTTP/1.1
Host: example.com

HTTP/1.1 405 Method Not Allowed
Allow: GET, HEAD
```

### ✅ Good Every other response MAY carry the field, so its absence says nothing

```http
POST /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Type: text/plain
```

### ❌ Bad The MUST's own subject — a 405 carrying no Allow at all

```http
POST /resource HTTP/1.1
Host: example.com

HTTP/1.1 405 Method Not Allowed
Content-Type: text/plain
```

### ❌ Bad The clause after "containing" — the list names the method the status refuses

```http
POST /resource HTTP/1.1
Host: example.com

HTTP/1.1 405 Method Not Allowed
Allow: GET, POST, HEAD
```
