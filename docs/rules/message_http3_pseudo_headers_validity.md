<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# HTTP/3 Pseudo-Headers Validity

## Description

HTTP/3 requests encode control data as pseudo-header fields. This rule validates that every request includes exactly one `:method` pseudo-header field and that every non-CONNECT request includes a non-empty `:path` pseudo-header field.

For schemes with a mandatory authority component (including `http` and `https`), the HTTP/3 specification requires that the request contain either an `:authority` pseudo-header field or a `Host` header field. This rule enforces that requirement by checking that at least one of `:authority` or `Host` is present. It does not validate the `:scheme` pseudo-header, because the canonical transaction model used by lint-http does not retain scheme information for origin-form requests.

**The deprecated userinfo subcomponent is reported where it can be seen.** RFC 9114 §4.3.1 forbids `:authority` from including it for URIs of scheme `http` or `https`, and the capture shows `:authority` only where the transport reassembled it into an absolute-form target — which is also the one place the scheme the sentence gates on is on the wire, so the gate and the evidence arrive together or not at all. A CONNECT's `:authority` is §4.4's host-and-port tunnel destination, with no scheme to gate on and no third component, so a userinfo in an authority-form target is reported outright — while an absolute-form CONNECT target is a conforming extended CONNECT and a malformed basic one with nothing in a capture to choose between them, and is declined here as the HTTP/2 twin declines it. Both findings withhold the password half (RFC 3986 §3.2.1). The twin sentence for HTTP/2 (RFC 9113 §8.3.1) is `message_http2_pseudo_headers_validity`'s.

**This rule reads requests only.** RFC 9114 §4.3.2 requires a response to carry exactly one `:status` pseudo-header field, which the canonical transaction model always supplies as a `u16`, so its absence has no representation here. The range that value must fall in is RFC 9110 §15's and is the same for every HTTP version — §4.3.2 states none of its own — so an out-of-range status is reported by `status_code_valid_range`, whatever version carried it. This rule used to report it too, but only when both ends spoke HTTP/3.

## Specifications

- [RFC 9114 §4.3](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.3): HTTP Control Data
- [RFC 9114 §4.3.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.3.1): Request Pseudo-Header Fields — the exactly-one MUST for `:method`, `:scheme` and `:path`, the `:authority`-or-Host requirement for schemes with a mandatory authority component, and the MUST NOT on the deprecated userinfo subcomponent for http and https URIs
- [RFC 3986 §3.2.1](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.1): User Information — the sentence asking an application not to render what follows the first colon of a userinfo, which is why both findings here withhold the password half
- [RFC 9114 §4.3.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.3.2): Response Pseudo-Header Fields
- [RFC 9114 §4.4](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.4): The CONNECT Method
- [RFC 9110 §7.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.1): Determining the Target Resource (asterisk-form request target)

## Configuration

```toml
[rules.message_http3_pseudo_headers_validity]
enabled = true
severity = "error"
```

## Examples

### ✅ Good

```http
GET /resource HTTP/3
Host: example.com
Accept: text/html
```

```http
OPTIONS * HTTP/3
Host: example.com
```

```http
CONNECT example.com:443 HTTP/3
```

```http
HTTP/3 200 OK
Content-Type: text/html
```

### ❌ Bad

```http
GET /resource HTTP/3
Accept: text/html
```

```http
 HTTP/3
Host: example.com
```

```http
GET * HTTP/3
Host: example.com
```

```http
HTTP/3 0
```

### ❌ Bad (the deprecated userinfo subcomponent in :authority)

```http
GET https://user@example.com/resource HTTP/3
```
