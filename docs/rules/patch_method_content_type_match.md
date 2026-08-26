<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Client PATCH Content-Type Matches Accept-Patch

## Description

Reports a `PATCH` request whose `Content-Type` names a patch document format that no `Accept-Patch` for this resource has mentioned.

**Why the advertisement is the only evidence.** RFC 5789 defines no default patch document format, no registry of them and no naming convention, so nothing in a lone `PATCH` says whether its media type is one a server takes — `patch_partial_update` requires the field and does not judge its value for exactly that reason. RFC 9110 §12.3 names where the answer lives: `Accept-Patch` "allows discovery of which content types are accepted in PATCH requests", and preferences a server sends in a response are "request content negotiation" because they "intend to influence selection of an appropriate content for subsequent requests to that resource".

**What makes an unlisted type a finding.** RFC 5789 places no requirement on the client: §3.1 says the presence of a format "indicates that that specific format is allowed", and §2.2 gives the server a `415 (Unsupported Media Type)` for one it does not support. The sentence that closes the list is RFC 9110 §12.4.3's — "[i]f no wildcard is present, values that are not explicitly mentioned in the field are considered unacceptable" — which reaches this field through §12.3. So the report is that the exchange contradicts itself: the client sent a format the server had already said it does not accept. It is not a disobeyed MUST or SHOULD, and there is none to disobey.

**There is no wildcard.** `Accept-Patch` is `1#media-type`. The asterisk forms are `Accept`'s `media-range` (RFC 9110 §12.5.1), a different production in a different field, and §12.4.3 makes wildcards a feature a field has only "where indicated". A server writing `Accept-Patch: */*` or `application/*` has therefore advertised a media type spelled with an asterisk; the finding says so when it happens, rather than treating it as permission.

**Which advertisement counts.** The most recent response *for this resource* that carried the field, whichever method drew it — §3.1 makes the field's presence "in response to any method" an indication about the resource, so an `OPTIONS` exchange several requests back still counts.

**What is not judged here.** The advertisement's syntax: members that do not parse as a media type are skipped, and a field with no parseable member leaves the rule unable to answer, so it declines. `server_patch_accept_patch_header` is the rule that reports a malformed `Accept-Patch`, on a response to any method — including the `OPTIONS` response §3.1 asks for it in, which nothing validated until that rule was audited. On the request side, more than one `Content-Type` line makes the comparison meaningless, because recipients differ over which member wins (§8.3); a value that is not a media type, and an absent one, are `message_content_type_well_formed`'s and `patch_partial_update`'s findings. Parameters are not compared: whether one is significant depends on the media type's registration (§8.3.1), so `text/example` and `text/example;charset=utf-8` are treated as the same format.

## Specifications

- [RFC 5789 §3.1](https://www.rfc-editor.org/rfc/rfc5789.html#section-3.1): The `Accept-Patch` header — the patch document formats a server accepts, advertised per resource and readable from a response to any method. This reference said §2.2, which is Error Handling
- [RFC 5789 §2.2](https://www.rfc-editor.org/rfc/rfc5789.html#section-2.2): Error handling — `415 (Unsupported Media Type)` is what a server may answer a format it does not support with, which is the consequence this rule anticipates rather than a requirement it enforces
- [RFC 9110 §12.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.3): Request content negotiation — enrols `Accept-Patch` among the preferences a server sends to influence the content of subsequent requests, which is what lets §12.4.3 reach it
- [RFC 9110 §12.4.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.4.3): Wildcard values — a field has one only where its own definition indicates one, and where none is present the values not mentioned are considered unacceptable. Both halves of this rule
- [RFC 9110 §8.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3): `Content-Type` is a singleton, and recipients differ over which member wins when it is sent more than once — so a duplicated field states no media type to compare
- [RFC 9110 §8.3.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.1): The `media-type` grammar: type and subtype are case-insensitive, and whether a parameter is significant depends on the media type's registration

## Configuration

```toml
[rules.patch_method_content_type_match]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good advertised by the OPTIONS response, and a parameter does not make a different format

```http
OPTIONS /example/buddies.xml HTTP/1.1
Host: www.example.com

HTTP/1.1 200 OK
Allow: GET, PUT, POST, OPTIONS, HEAD, DELETE, PATCH
Accept-Patch: application/example, text/example

PATCH /example/buddies.xml HTTP/1.1
Host: www.example.com
Content-Type: text/example;charset=utf-8
Content-Length: 11

[patch doc]
```

### ❌ Bad a format the advertisement never mentioned

```http
OPTIONS /example/buddies.xml HTTP/1.1
Host: www.example.com

HTTP/1.1 200 OK
Accept-Patch: application/example, text/example

PATCH /example/buddies.xml HTTP/1.1
Host: www.example.com
Content-Type: application/merge-patch+json
Content-Length: 11

[patch doc]
```
