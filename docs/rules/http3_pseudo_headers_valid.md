<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# HTTP/3 Pseudo-Headers Validity

## Description

HTTP/3 requests encode control data as pseudo-header fields. This rule reads what each of them conveyed, and the first thing it checks is that every non-CONNECT request includes a non-empty `:path` pseudo-header field.

**A request naming no method at all is not reported here.** §4.3.1 requires exactly one `:method`, and over this version an absent one and an empty one reassemble into the same capture: a method of no characters, which is `method = token`'s one-character floor. `request_method_token_valid` reports that on every version, so the finding is left there rather than given a second name; what a value naming no method does here is stop the rule, since neither the CONNECT restrictions nor the asterisk's one method have anything to turn on. `http2_pseudo_headers_valid` surrendered the same question earlier and for the same reason.

For schemes with a mandatory authority component (including `http` and `https`), the HTTP/3 specification requires that the request contain either an `:authority` pseudo-header field or a `Host` header field. This rule enforces that requirement by checking that at least one of `:authority` or `Host` is present. **A CONNECT is asked the same question once**: §4.4 puts the host and port of the tunnel destination in `:authority`, a capture shows that field reassembled into the target — or, where a library moved it, as a `Host` field — and a request carrying neither names nothing to open a tunnel to. That is one finding whether the target arrived empty, as a path or as an asterisk, since the shape says what the sender attempted rather than what a recipient is missing; it used to be three, answered differently from how the HTTP/2 twin answered them. It does not validate the `:scheme` pseudo-header, because the canonical transaction model used by lint-http does not retain scheme information for origin-form requests.

**The deprecated userinfo subcomponent is reported where it can be seen.** RFC 9114 §4.3.1 forbids `:authority` from including it for URIs of scheme `http` or `https`, and the capture shows `:authority` only where the transport reassembled it into an absolute-form target — which is also the one place the scheme the sentence gates on is on the wire, so the gate and the evidence arrive together or not at all. A CONNECT's `:authority` is §4.4's host-and-port tunnel destination, with no scheme to gate on and no third component, so a userinfo in an authority-form target is reported outright — while an absolute-form CONNECT target is a conforming extended CONNECT and a malformed basic one with nothing in a capture to choose between them, and is declined here as the HTTP/2 twin declines it. Both findings withhold the password half (RFC 3986 §3.2.1). The twin sentence for HTTP/2 (RFC 9113 §8.3.1) is `http2_pseudo_headers_valid`'s.

**This rule reads requests only.** RFC 9114 §4.3.2 requires a response to carry exactly one `:status` pseudo-header field, which the canonical transaction model always supplies as a `u16`, so its absence has no representation here. The range that value must fall in is RFC 9110 §15's and is the same for every HTTP version — §4.3.2 states none of its own — so an out-of-range status is reported by `status_code_valid_range`, whatever version carried it. This rule used to report it too, but only when both ends spoke HTTP/3.

## Specifications

- [RFC 9114 §4.3](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.3): HTTP Control Data
- [RFC 9114 §4.3.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.3.1): Request Pseudo-Header Fields — the exactly-one MUST for `:method`, `:scheme` and `:path`, the `:authority`-or-Host requirement for schemes with a mandatory authority component, and the MUST NOT on the deprecated userinfo subcomponent for http and https URIs
- [RFC 9113 §8.3.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.1): Request Pseudo-Header Fields — what each of `:method`, `:scheme`, `:authority` and `:path` conveys, the `'*'` value for asterisk-form OPTIONS, the `:path`-must-not-be-empty MUST, and the userinfo MUST NOT written for `http` and `https` targets
- [RFC 9110 §9.3.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.3.6): CONNECT — the host and port number of the tunnel destination, the absence of a default port, and the server's MUST to reject an empty or invalid one. This is where the port requirements come from; the grammar states none.
- [RFC 3986 §3.2.1](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.1): User Information — the sentence asking an application not to render what follows the first colon of a userinfo, which is why both findings here withhold the password half
- [RFC 9114 §4.3.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.3.2): Response Pseudo-Header Fields
- [RFC 9114 §4.4](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.4): The CONNECT Method — the MUST that a CONNECT request be constructed with `:scheme` and `:path` omitted and `:authority` carrying the host and port to connect to, and the sentence making a request that does not malformed
- [RFC 9113 §8.5](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.5): The CONNECT Method — `:method` is set to CONNECT, `:scheme` and `:path` are omitted, `:authority` carries the host and port, and the proxy opens a TCP connection to them
- [RFC 9110 §7.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.1): Determining the Target Resource — the two method-specific forms, the MUST NOT that keeps each to its method, and the reconstruction being specific to each major protocol version
- [RFC 3986 §3.1](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.1): Scheme — `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`, the name before the first colon
- [RFC 3986 §3.2.2](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.2): Host — `host = IP-literal / IPv4address / reg-name`, where the square brackets of the IP literal are the only ones the URI syntax admits anywhere
- [RFC 3986 §3.2.3](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.3): Port — `port = *DIGIT`, which has no lower bound, no upper bound, and admits the empty string

## Configuration

```toml
[rules.http3_pseudo_headers_valid]
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
GET * HTTP/3
Host: example.com
```

### ❌ Bad (the deprecated userinfo subcomponent in :authority)

```http
GET https://user@example.com/resource HTTP/3
```
