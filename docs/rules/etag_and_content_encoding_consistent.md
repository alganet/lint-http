<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# A strong ETag belongs to one content coding

## Description

Reports a strong entity tag that a server sent on two `200` responses for the same resource whose content codings differ — `Content-Encoding: br` on one and none on the other, or `gzip` on one and `br` on the other.

**A content coding is part of the representation data.** RFC 9110 §8.8.1 gives exactly this pairing as its example of a validator that is weak, whatever it is labelled: *"if the origin server sends the same validator for a representation with a gzip content coding applied as it does for a representation with no content coding, then that validator is weak."* §8.8.3.3 says why the label matters: a cache updating a stored response after a `304`, and a client resuming a download with `If-Range`, both take a matching strong tag to mean the octets they hold are the octets the server would send. Under a shared tag, the second half of one coding is spliced onto the first half of the other.

**The usual cause is compression added after the tag was computed** — a server or a CDN edge that compresses on the way out and passes the origin's tag through. Two repairs work: a distinct tag per coding (the §8.8.3.3 example appends a suffix), or marking the tag weak with `W/`, which is what several servers do when they compress on the fly.

**What is compared.** Only `GET` requests answered `200`: a `HEAD` response may leave out a field that is determined while generating content (§9.3.2), and a `206` carries a part of a representation rather than a whole one. Two responses are the same resource when they answer the same client for the same target URI. The codings are compared as lists — case-insensitively, with `identity` and empty members dropped — so `gzip` and `GZIP` are one coding and `gzip, br` and `br, gzip` are two. A weak tag is never reported: sharing is what `W/` permits.

**Not this rule's.** Two media types under one strong tag are allowed — §8.8.1 says representations differing only in metadata may share one. Whether the tag is well formed is `etag_syntax`'s.

## Violations

- [etag_conflicting](../violations/etag_conflicting.md) — One strong entity tag names two content codings

## Specifications

- [RFC 9110 §8.8.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.1): Weak versus Strong — a validator shared by two representations of a resource at the same time is weak unless their data is identical, and a gzip-coded and an unencoded representation are the example
- [RFC 9110 §8.8.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.8.3): Entity Tags — `entity-tag = [ weak ] opaque-tag`, `weak = %s"W/"` (case-sensitive by the `%s` prefix), `opaque-tag = DQUOTE *etagc DQUOTE`, and `etagc` as VCHAR minus the DQUOTE plus obs-text

## Configuration

```toml
[rules.etag_and_content_encoding_consistent]
enabled = true
```

## Examples

### ✅ Good — a distinct tag per coding

```http
GET /a HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
ETag: "123-a"
Vary: Accept-Encoding

GET /a HTTP/1.1
Host: example.com
Accept-Encoding: gzip

HTTP/1.1 200 OK
ETag: "123-b"
Content-Encoding: gzip
Vary: Accept-Encoding
```

### ✅ Good — one weak tag for both

```http
GET /a HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
ETag: W/"123"
Vary: Accept-Encoding

GET /a HTTP/1.1
Host: example.com
Accept-Encoding: gzip

HTTP/1.1 200 OK
ETag: W/"123"
Content-Encoding: gzip
Vary: Accept-Encoding
```

### ❌ Bad — the unencoded and the gzip response share a strong tag

```http
GET /a HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
ETag: "123"
Vary: Accept-Encoding

GET /a HTTP/1.1
Host: example.com
Accept-Encoding: gzip

HTTP/1.1 200 OK
ETag: "123"
Content-Encoding: gzip
Vary: Accept-Encoding
```
