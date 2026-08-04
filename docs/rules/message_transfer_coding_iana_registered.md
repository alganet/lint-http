<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Transfer Coding Iana Registered

## Description

Validate `Transfer-Encoding` and `TE` header values to ensure transfer-coding tokens are syntactically valid and are recognised (SHOULD be IANA-registered or explicitly allowed via configuration). The `TE` header's special value `trailers` is accepted.

**Every field line of both fields is read**, since each is a list whose members may be spread across lines — and for `Transfer-Encoding` a second field line is the shape request smuggling arrives in, so reading only the first is the one omission this rule cannot afford. Values are decoded from the raw octets: an octet outside visible US-ASCII is not a `tchar`, so where a coding name belongs it is reported rather than used as a reason to skip the line.

**Members are split on commas that are not inside a quoted-string.** `transfer-parameter = token BWS "=" BWS ( token / quoted-string )`, so `chunked;ext="a,b"` is one coding carrying one parameter, not two members. Quoting that never closes leaves the members undelimitable and is reported here rather than passed over, because no other rule reports a malformed `Transfer-Encoding`.

**`chunked` is reported in `TE` and only there.** RFC 9112 §7.4: "A client MUST NOT send the chunked transfer coding name in TE; chunked is always acceptable for HTTP/1.1 recipients." It is a registered coding, so the registry check waves it through; this is the one place where a recognised name is still the wrong name. In `Transfer-Encoding` it is the ordinary case.

## Specifications

- [RFC 9112 §6.1](https://www.rfc-editor.org/rfc/rfc9112.html#section-6.1): Transfer Coding
- [RFC 9110 §10.1.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.4): TE header
- [IANA HTTP Parameters](https://www.iana.org/assignments/http-parameters/http-parameters.xhtml#transfer-coding): IANA Transfer Coding registry

## Configuration

```toml
[rules.message_transfer_coding_iana_registered]
enabled = true
severity = "warn"
allowed = ["chunked", "gzip", "deflate"]
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Transfer-Encoding: chunked

0
```

### ✅ Good (TE request)

```http
GET / HTTP/1.1
Host: example.com
TE: trailers
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Transfer-Encoding: x-custom
```
