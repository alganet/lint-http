<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Content Transfer Encoding Valid

## Description

Flags any `Content-Transfer-Encoding` header in an HTTP message. HTTP does not use this field: it belongs to MIME, and a gateway from a MIME-compliant protocol is required to remove it before the message reaches an HTTP client, so one arriving over HTTP means that removal did not happen.

The consequence is silent corruption rather than a mere style problem — an HTTP recipient ignores the field, so a body that was (say) base64-encoded for MIME transport is read without being decoded.

The value is reported as detail: a single `token` naming one of `7bit`, `8bit`, `binary`, `quoted-printable`, `base64` (case-insensitive), or a private `x-` mechanism, is well-formed MIME — but being well-formed MIME does not make the field belong in HTTP.

## Specifications

- [RFC 9112 §B.5](https://www.rfc-editor.org/rfc/rfc9112.html#appendix-B.5): Why the field is reported at all: HTTP does not use Content-Transfer-Encoding, and gateways from MIME-compliant protocols must remove it
- [RFC 2045 §6.1](https://www.rfc-editor.org/rfc/rfc2045.html#section-6.1): The MIME `mechanism` grammar the value is described against — five named encodings plus `ietf-token` / `x-token`, all case-insensitive
- [RFC 2045 §6.3](https://www.rfc-editor.org/rfc/rfc2045.html#section-6.3): Private mechanisms must be spelled with an `X-` prefix, which is why an `x-` value is well-formed MIME rather than an unrecognized one

## Configuration

```toml
[rules.content_transfer_encoding_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good HTTP carries no transfer encoding of its own here

```http
HTTP/1.1 200 OK
Content-Type: application/octet-stream

<response body>
```

### ❌ Bad well-formed MIME, but HTTP does not use the field

```http
HTTP/1.1 200 OK
Content-Transfer-Encoding: base64

<response body>
```

### ❌ Bad not a MIME mechanism either

```http
HTTP/1.1 200 OK
Content-Transfer-Encoding: no-such-mechanism

<response body>
```
