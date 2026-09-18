<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server ETag or Last-Modified Present

## Description

This rule checks if `200 OK` responses to `GET` and `HEAD` include either an `ETag` or a `Last-Modified` header.

These headers act as validators, allowing clients to perform conditional requests (`If-None-Match` or `If-Modified-Since`). This enables efficient caching and revalidation, significantly reducing bandwidth when resources haven't changed.

Only a `GET` or a `HEAD` is asked, because both sentences the rule rests on are about the *selected representation* — what RFC 9110 §3.2 defines as the representation a `GET` would select, and the thing a conditional request is evaluated against. §15.3.1 tabulates what a `200`'s content is for every other method: the status of an action for `POST`, `PUT` and `DELETE`, the communication options for `OPTIONS`, the request echoed back for `TRACE`. None of those is a representation a later request could validate, and a `200` to `OPTIONS` or `TRACE` is not cacheable at all (§9.3.7, §9.3.8), so no validator was owed on them. A `POST` response that names its own target in `Content-Location` is the one cacheable exception (§9.3.3) and is not read; it stays silent here.

## Violations

- [validator_missing](../violations/validator_missing.md) — A response gives a later request nothing to validate against

## Specifications

- [RFC 9110 §8.8.2.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.2.1): Generation: an origin server SHOULD send Last-Modified for any selected representation whose last modification date can be reasonably and consistently determined
- [RFC 9110 §8.8.3.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.3.1): Generation: an origin server SHOULD send an ETag for any selected representation for which detection of changes can be reasonably and consistently determined
- [RFC 9110 §3.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-3.2): Representations — the "selected representation" is what a GET would select, and it is what conditional requests are evaluated against; a 200 answering any other method carries no such thing
- [RFC 9110 §15.3.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.1): 200 (OK): a 200 is expected to contain content "unless the message framing explicitly indicates that the content has zero length" — the reported state is that exception, not a breach — and the 204 advice is an "ought to" conditioned on the request preferring no content, which is not observable

## Configuration

```toml
[rules.etag_or_last_modified_present]
enabled = true
```

## Examples

### ✅ Good Response (ETag)

```http
HTTP/1.1 200 OK
Content-Type: image/png
ETag: "33a64df551425fcc55e4d42a148795d9f25f89d4"
```

### ✅ Good Response (Last-Modified)

```http
HTTP/1.1 200 OK
Content-Type: text/html
Last-Modified: Wed, 21 Oct 2015 07:28:00 GMT
```

### ❌ Bad Response

```http
HTTP/1.1 200 OK
Content-Type: image/png
# Missing both ETag and Last-Modified
```
