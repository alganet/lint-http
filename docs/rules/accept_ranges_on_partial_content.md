<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Accept Ranges On Partial Content

## Description

Advice a client was given, and whether the next request took it. `Accept-Ranges` tells a client which range units a resource supports, or that it supports none — and almost everything this rule has to say about the request that follows is advice, because RFC 9110 §14.3 says the field "only provides advice for the sake of improving performance and reducing unnecessary network transfers".

**`Accept-Ranges: none` followed by a `Range` request** is the one finding addressed to the client. The permission to send `none` is granted to a server that supports no kind of range request "to advise the client not to attempt a range request on the same request path", and this request attempts one. It is still advice: the same section says a client "MAY generate range requests regardless of having received an Accept-Ranges field".

**A `Range` in a unit the previous response did not advertise** is advice about a wasted transfer. §14.2 says an origin server "MUST ignore a Range header field that contains a range unit it does not understand", so such a request is answered with the whole representation — which is what the advertisement exists to prevent. Nothing makes the advertised list exhaustive, so this is not a violation either.

**What this rule no longer reports.** A `Range` request following a 206 that carried no `Accept-Ranges` field: §14.3's "regardless of having received an Accept-Ranges field" permits it in as many words, and §14 makes range requests an OPTIONAL feature of HTTP altogether. Whether the advertised value is a well-formed list of range units belongs to `accept_ranges_values_valid`; whether the `Range` value is a well-formed ranges-specifier belongs to `range_header_syntax`. Where either value cannot be read as this rule needs it, it declines rather than reporting the field a second time — but a `Range` field that cannot be read is still a range request, and still takes the `none` advice.

**What no rule can check.** §14.3 also says a client "MUST NOT assume that receiving an Accept-Ranges field means that future range requests will return partial responses", and §15.3.7 that a client "MUST inspect a 206 response's Content-Type and Content-Range field(s)". Both are requirements on a conclusion the client drew; nothing on the wire distinguishes a client that assumed from one that did not, so this rule stops there rather than approximating them.

**What it reads, and what that assumes.** The transaction immediately preceding this one from the same client for the same request URI, which is what "the same request path" is measured against; a later response supersedes what an earlier one advised, so only the most recent is read. `Accept-Ranges` is read from the trailer section as well as the header section, which §14.3 permits. Two assumptions come with that and are worth knowing before enabling this rule. *The same client* is an address and a `User-Agent` string, so several user agents behind one address that send the same `User-Agent` are one client here, and advice given to one of them is measured against another's request. And the rule's name is historical: nothing it checks depends on the previous response being a `206 Partial Content`, and after the corrections above it does not read the status code at all.

## Specifications

- [RFC 9110 §14.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.3): `Accept-Ranges`: advice, in the section's own words, about which range units a resource supports — or `none`, which advises against attempting a range request on the same request path. A client MAY send range requests regardless, and MUST NOT assume the field means future range requests will be answered with partial responses, which no parser can check
- [RFC 9110 §14.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.2): `Range`: `ranges-specifier`, and an origin server MUST ignore one whose range unit it does not understand — which is what a request in an unadvertised unit costs
- [RFC 9110 §14.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.1): Range units: `range-unit = token`, shared by `Accept-Ranges` and `Range`, and case-insensitive — which is why both sides of the comparison are folded
- [RFC 9110 §15.3.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.7): `206 Partial Content`: a client MUST inspect its `Content-Type` and `Content-Range`, which is not observable either. A 206 that advertised nothing is no longer reported here. RFC 7233 §4.1 defined the status code; RFC 9110 obsoleted RFC 7233

## Configuration

```toml
[rules.accept_ranges_on_partial_content]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good — the server advertised bytes and the client asks in bytes

```http
HTTP/1.1 200 OK
Accept-Ranges: bytes

GET /resource HTTP/1.1
Range: bytes=0-499
```

### ✅ Good — a client MAY generate range requests regardless of having received the field

```http
HTTP/1.1 206 Partial Content
Content-Range: bytes 0-499/1234

GET /resource HTTP/1.1
Range: bytes=500-999
```

### ❌ Bad — advice: the server advised against range requests on this path

```http
HTTP/1.1 200 OK
Accept-Ranges: none

GET /resource HTTP/1.1
Range: bytes=0-499
```

### ❌ Bad — advice: a unit the previous response did not advertise

```http
HTTP/1.1 200 OK
Accept-Ranges: bytes

GET /resource HTTP/1.1
Range: pages=1-2
```
