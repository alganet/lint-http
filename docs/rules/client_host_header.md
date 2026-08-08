<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Client Host Header

## Description

This rule reads the request's `Host` header field: whether it is there, whether it is there once, and whether its value is what `Host = uri-host [ ":" port ]` generates.

- A request that carries no `Host` field is reported **unless it is an HTTP/2 or HTTP/3 request that sent an `:authority` pseudo-header** — RFC 9110 §7.2's MUST is written with that exception, and RFC 9112 §3.2's is written for HTTP/1.1 messages. An HTTP/1.1 request in absolute-form is not exempt: RFC 9112 §3.2.2 requires the field there too.
- `Host` is not a list field, so two field lines of it are not one value; RFC 9110 §5.3 forbids a sender from generating them and RFC 9112 §3.2 has the recipient answer 400.
- The value must be a `uri-host` (RFC 3986 §3.2.2) and, if a port follows the colon, a port. An IPv6 address must be inside square brackets — that is the only thing distinguishing an IP literal from a registered name.
- A userinfo subcomponent and its `@` are reported: RFC 9112 §3.2 requires the field value to be the authority component *excluding* them.

Three things this rule deliberately does **not** report:

- **An empty field value.** `reg-name` is `*( unreserved / pct-encoded / sub-delims )`, so a host of no characters is one, and RFC 9112 §3.2 *requires* an empty `Host` when the target URI's authority component is missing or undefined. A server facing one reconstructs an empty authority and may reject the request (RFC 9112 §3.3), but nothing makes the client's field a syntax error.
- **A port outside the TCP range.** The production is `port = *DIGIT` (RFC 3986 §3.2.3) — no lower bound, no upper bound, and zero digits is a port, which is why `Host: example.com:0`, `Host: example.com:99999` and `Host: example.com:` are not findings here. `Host: example.com:abc` is, because it is not `*DIGIT`.
- **Where the field sits in the header section.** RFC 9110 §7.2 says a user agent that sends `Host` SHOULD send it as the first field, and RFC 9110 §5.3 calls it good practice; the captured transaction holds its fields in a map whose iteration order is not the order they arrived in, so no check here can decide it.

## Specifications

- [RFC 9110 §7.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.2): Host and :authority — the grammar, the MUST, and the pseudo-header the MUST excepts. The SHOULD to send Host first is not checked: the capture does not preserve field order.
- [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3): Field Order — a sender MUST NOT repeat a field name unless the field is a comma-separated list, and Host is not one
- [RFC 9112 §3.2](https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2): Request Target — Host is required in all HTTP/1.1 requests, its value excludes userinfo, and it is empty when the target URI has no authority
- [RFC 3986 §3.2.2](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.2): Host — an IP literal is distinguished by its square brackets; every other host is a registered name
- [RFC 3986 §3.2.3](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.2.3): Port — `port = *DIGIT` bounds nothing, so a port outside the TCP range is not a syntax finding

## Configuration

```toml
[rules.client_host_header]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good A registered name and a port

```http
GET /path HTTP/1.1
Host: example.com:8080
```

### ✅ Good An IPv6 literal, inside the brackets that identify it

```http
GET /path HTTP/1.1
Host: [::1]:443
```

### ✅ Good A port no TCP connection could use is still `*DIGIT`

```http
GET /path HTTP/1.1
Host: example.com:99999
```

### ❌ Bad A port that is not digits

```http
GET /path HTTP/1.1
Host: example.com:abc
```

### ❌ Bad An IPv6 address with nothing marking where it ended

```http
GET /path HTTP/1.1
Host: fe80::1
```

### ❌ Bad The authority component, userinfo and all

```http
GET /path HTTP/1.1
Host: user:pass@example.com
```

### ❌ Bad A character no host production generates

```http
GET /path HTTP/1.1
Host: exa mple.com
```
