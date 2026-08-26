<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Request Target Form Valid

## Description

Reads an HTTP/1.x request-line's request-target and asks two things: which of the four forms it derives from, and whether the method it was sent with may use that form.

`request-target = origin-form / absolute-form / authority-form / asterisk-form` (RFC 9112 §3.2). A target derives from at least one of the four or from none, and "none" is reported: RFC 9110 §2.2 forbids a sender from generating a protocol element that matches no ABNF rule, and RFC 9112 §3.2 has the recipient of an invalid request-line answer 400 (Bad Request). An empty request-target is reported the same way, whatever the method — every one of the four derives at least one character.

**Two of the forms belong to one method each.** RFC 9110 §7.1 states both and closes with "These forms MUST NOT be used with other methods": the asterisk is a server-wide OPTIONS request's target, and a host and port is a CONNECT's. So `GET *` and `GET 192.0.2.1:443` are reported, and so is a CONNECT whose target is a path, a full URI, or anything else that is not a host and port. The method is compared as written, because the method token is case-sensitive (RFC 9110 §9.1) — `connect` is not CONNECT and owns neither form.

**A CONNECT's host and port are both required, and the grammar requires neither.** `authority-form = uri-host ":" port` is built from two `*`-quantified productions: `port` is `*DIGIT` (RFC 3986 §3.2.3) and `reg-name` is `*( unreserved / pct-encoded / sub-delims )`, so `example.com:`, `:443` and even `:` all derive from it. The name and the number are asked for in prose — RFC 9112 §3.2.3's "It consists of only the uri-host and port number of the tunnel destination, separated by a colon" and its sentence sending the scheme's default port when the target URI elides one, and RFC 9110 §7.1's "the host name and port number of the tunnel destination". Each missing half is reported as itself; a target with no colon at all is reported as not being a host and port.

**Some targets derive from two forms, and the finding says so rather than picking one.** `scheme` is `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )` and `hier-part` admits a rootless path, so anything shaped `<scheme>:<digits>` is an `absolute-URI` as well as a `uri-host ":" port` — `example.com:443`, and `tel:8005551212` and `urn:123` exactly as much. Nothing in the request-line chooses between them, so the report states both readings: as a host and port it is a form only CONNECT may use, and as an absolute-URI it asks a proxy for a resource in a scheme named after the left half. Two recipients on one chain may route it two ways, and that is the finding. Where the left half is one no `scheme` generates — `192.0.2.1:443`, `[2001:db8::1]:443`, `:80` — there is no ambiguity and the report says outright that the form is CONNECT's.

**Whitespace is reported on its own, and so is a CR, LF or FF.** RFC 9112 §3.2 excludes whitespace from the request-target by name, one paragraph below the four forms, and gives the reason: the request-line is malformed, and a recipient is asked not to autocorrect it because it might be deliberately crafted to bypass a security filter along the request chain. The check covers the wider class because no component of any of the four forms admits a CR, LF or FF either, and because this rule reads no path characters — without it, `/pa%0Dth` sent raw would pass as an ordinary absolute path.

**What this rule does not decide.**

- **Whether origin-form or absolute-form was the right choice.** §3.2.1 requires the absolute path and query when the request goes directly to an origin server, and §3.2.2 requires the full target URI when it goes to a proxy — and no captured message says which the client believed it was addressing. Both are therefore accepted from every method other than CONNECT. §3.2.2's "A server MUST accept the absolute-form in requests even though most HTTP/1.1 clients will only send the absolute-form to a proxy" is why that silence is the right answer rather than a tolerance.
- **What is inside a path, query or scheme.** A leading `/` is the whole of the origin-form test here; `request_target_no_fragment` and `request_uri_percent_encoding_valid` read the characters. A scheme is checked for being a scheme, not for being one anybody serves.
- **Anything sent over HTTP/2 or HTTP/3.** Those versions carry the request target's components in pseudo-header fields, where the asterisk is a `:path` value (RFC 9113 §8.3.1, RFC 9114 §4.3.1) and a CONNECT's destination is an `:authority` with no `:path` at all. A capture of such a request holds the target URI its transport reassembled, not a request-target, so an asterisk arrives inside an authority and measuring it against these productions would report the reassembly rather than the sender. `message_http2_pseudo_headers_validity` and `message_http3_pseudo_headers_validity` are the rules that read pseudo-header fields, and the second of them asks §7.1's question about the asterisk in its own version's terms.
- **A CONNECT this proxy itself handled.** A CONNECT request is answered by the tunnel and never becomes a transaction here, so the CONNECT findings above are reachable only in a capture recorded elsewhere and read back in.

## Specifications

- [RFC 9112 §3.2](https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2): Request Target: the four forms, and the exclusion of whitespace from all of them
- [RFC 9112 §3.2.3](https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2.3): authority-form: CONNECT's target, and where the port number is asked for in prose rather than in the grammar
- [RFC 9112 §3.2.4](https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2.4): asterisk-form: the server-wide OPTIONS request's target
- [RFC 9110 §7.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.1): Determining the Target Resource: the two method-specific forms, the MUST NOT that keeps each to its method, and the reconstruction being specific to each major protocol version
- [RFC 9110 §2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2): The sender's MUST NOT against generating protocol elements outside the ABNF, which is what makes a target in none of the four forms a violation

## Configuration

```toml
[rules.request_target_form_valid]
enabled = true
severity = "error"
```

## Examples

### ✅ Good Request

```http
OPTIONS * HTTP/1.1
CONNECT www.example.com:80 HTTP/1.1
GET /where?q=now HTTP/1.1
GET http://www.example.org/pub/WWW/TheProject.html HTTP/1.1
```

### ❌ Bad Request

```http
GET * HTTP/1.1
GET 192.0.2.1:443 HTTP/1.1
GET example.com:443 HTTP/1.1
CONNECT /not-a-host-and-port HTTP/1.1
CONNECT www.example.com: HTTP/1.1
```
