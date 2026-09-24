<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# A resource's default response names the fields its siblings vary on

## Description

Reports a resource whose responses disagree about what selects them: one names a request field in `Vary`, and another — sent to a request that did not carry the field — does not.

**RFC 9111 §4.1 names this as a mistake.** *"Some resources mistakenly omit the Vary header field from their default response (i.e., the one sent when the request does not express any preferences), with the effect of choosing it for subsequent requests to that resource even when more preferable responses are available."* The common shape is a server that adds `Vary: Accept-Encoding` only when it compresses: its answer to a request without `Accept-Encoding` goes out with no `Vary`, a cache stores it, and every later client gets the uncompressed body. The same shape with `Cookie` hands the anonymous page to a signed-in user.

**Which responses are compared.** Two responses to `GET`s from the same client for the same target URI, both with the same status code, both of which a cache could have stored (RFC 9111 §3). A `Vary: *` on either side is no list to compare. A field counts as absent from a request only where the request carried no line of it at all.

**One finding for each response that omits the field.** When the omitting response arrives after one that named the field, the finding is on it. When it arrived first, the finding is on the first response that names the field, naming the earlier one — and not again on every response after that, so a resource that was wrong once is reported once.

**Not this rule's.** A `206` or a `304` that leaves out the `Vary` its `200` carried is `status_206_required_fields`' and `status_304_required_fields`'. A coded response without `Accept-Encoding` in `Vary` is `vary_and_content_encoding_consistent`'s, whatever its siblings say.

## Violations

- [vary_conflicting](../violations/vary_conflicting.md) — A default response omits a field its siblings name in Vary

## Specifications

- [RFC 9111 §4.1](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.1): Calculating Cache Keys with the Vary Header Field — a resource whose default response omits Vary has that response chosen for later requests even when a more preferable one is available

## Configuration

```toml
[rules.vary_consistent]
enabled = true
```

## Examples

### ✅ Good — the default response names the field too

```http
GET /a HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Vary: Accept-Encoding
Cache-Control: max-age=600

GET /a HTTP/1.1
Host: example.com
Accept-Encoding: gzip

HTTP/1.1 200 OK
Content-Encoding: gzip
Vary: Accept-Encoding
Cache-Control: max-age=600
```

### ❌ Bad — Vary only when the response was compressed

```http
GET /a HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Cache-Control: max-age=600

GET /a HTTP/1.1
Host: example.com
Accept-Encoding: gzip

HTTP/1.1 200 OK
Content-Encoding: gzip
Vary: Accept-Encoding
Cache-Control: max-age=600
```
