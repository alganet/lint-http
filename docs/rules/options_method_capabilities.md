<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Semantic OPTIONS Method Capabilities

## Description

Reports the two requirements RFC 9110 §9.3.7 places on an OPTIONS exchange that a captured message can answer. An OPTIONS request asks "about the communication options available for the target resource", so what the exchange is for is the advertisement in the response.

**A request carrying content must say what it is.** §9.3.7: "A client that generates an OPTIONS request containing content MUST send a valid Content-Type header field describing the representation media type." Content is §6.4's — the stream of octets after the header section, counted once framing has been taken off — so a `Transfer-Encoding: chunked` is not by itself content, and over HTTP/2 and HTTP/3 content arrives with no framing field at all. Where a body was captured its octet count decides; otherwise the request's own `Content-Length` does, which leaves a chunked request whose octets were not captured unmeasurable. Only the field's *absence* is reported here: a `Content-Type` that is empty or is not a media type is `message_content_type_well_formed`'s finding. The section adds that "this specification does not define any use for such content", so the requirement is about labelling what was sent, not about sending it.

**A successful response should advertise something.** §9.3.7: "A server generating a successful response to OPTIONS SHOULD send any header that might indicate optional features implemented by the server and applicable to the target resource (e.g., Allow), including potential extensions not defined by this specification." That names a class, not a field, so this rule does not ask for `Allow` — §10.2.1 makes `Allow` a **MAY** on every response other than a 405, and the 405 that requires it is `status_405_allow_valid`'s. The finding is a successful response carrying none of the three fields a specification names as advertising an optional feature applicable to the target resource: `Allow` (§10.2.1), `Accept-Ranges` (§14.3), and `Accept-Patch` (RFC 5789 §3.1, which asks for it in an OPTIONS response by name). Presence is the whole test — §10.2.1 gives an empty `Allow` value the meaning "the resource allows no methods", which is an answer. `Accept-Ranges` also counts when it arrives in the trailer section, because §14.3 says it MAY be sent there; the other two are read from the header section only, since §6.5.1 forbids a trailer field unless the field's own definition permits it and neither definition does.

**The limit of that finding.** The sentence ends by including "potential extensions not defined by this specification", so the class is open and no list can close it. A server advertising a capability under a field name this rule does not know reads here exactly like a server advertising nothing. Read the finding as "nothing recognizable was advertised", not as a violation of the SHOULD.

**Not checked: an asterisk target.** §9.3.7 says an OPTIONS request with `*` as the request target "applies to the server in general rather than to a specific resource", and the SHOULD asks for headers applicable to the target resource. Such a response is not measured — **over HTTP/1.1**. Over HTTP/3 the capture does not keep the form: the request target is recorded as the string form of a URI rebuilt from `:scheme`, `:authority` and `:path`, so a `:path` of `*` arrives as `https://example.com*` and the asterisk is no longer distinguishable from part of the authority. An `OPTIONS *` over HTTP/3 is therefore measured, and may be reported for advertising nothing when there was nothing to advertise.

**Not checked: where `Max-Forwards` came from.** §9.3.7's "A proxy MUST NOT generate a Max-Forwards header field while forwarding a request unless that request was received with a Max-Forwards field" is about who wrote a field, and no field of a message records its author. A capture cannot distinguish a client's `Max-Forwards` from one an intermediary invented.

## Specifications

- [RFC 9110 §9.3.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.7): OPTIONS — the client `MUST` about `Content-Type`, the `SHOULD` to advertise, which names a class ending "including potential extensions not defined by this specification" rather than a field, the asterisk target that names no resource, and the `Max-Forwards` `MUST NOT` no capture can attribute
- [RFC 9110 §9.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.1): The method token is case-sensitive, which is why `OPTIONS` is matched exactly and a lowercase `options` is not an OPTIONS
- [RFC 9110 §6.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-6.4): Content — the octet stream left after framing is removed, which is what the `Content-Type` check measures instead of the presence of a framing field
- [RFC 9110 §15.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3): 2xx is the class named Successful, which is the range "a successful response to OPTIONS" means
- [RFC 9110 §10.2.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.1): `Allow` advertises the target resource's methods, is a `MAY` on any response other than a 405 — so it is not asked for by name — and an empty value of it means the resource allows no methods
- [RFC 9110 §14.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.3): `Accept-Ranges` advertises range-request support for the target resource — a second member of the class §9.3.7 asks for
- [RFC 5789 §3.1](https://www.rfc-editor.org/rfc/rfc5789.html#section-3.1): `Accept-Patch` advertises the patch formats a resource accepts, and this section asks for it in an OPTIONS response by name

## Configuration

```toml
[rules.options_method_capabilities]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good The methods of the target resource

```http
OPTIONS /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Allow: GET, POST, OPTIONS
```

### ✅ Good A capability other than the method set — the class is what the SHOULD names

```http
OPTIONS /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Accept-Patch: application/json-patch+json
```

### ✅ Good An asterisk target names no resource, so nothing is asked of the response

```http
OPTIONS * HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Length: 0
```

### ✅ Good Content in the request, labelled

```http
OPTIONS /resource HTTP/1.1
Host: example.com
Content-Type: application/json
Content-Length: 2

{}

HTTP/1.1 200 OK
Allow: GET, OPTIONS
```

### ❌ Bad A successful response that advertises nothing recognizable

```http
OPTIONS /resource HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 0
```

### ❌ Bad Content in the request with nothing saying what it is

```http
OPTIONS /resource HTTP/1.1
Host: example.com
Content-Length: 2

{}

HTTP/1.1 200 OK
Allow: GET, OPTIONS
```
