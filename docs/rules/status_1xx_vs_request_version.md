<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# The interim response a client's version defined none of

## Description

RFC 9110 §15.2 states one MUST NOT about the whole informational class: "Since HTTP/1.0 did not define any 1xx status codes, a server MUST NOT send a 1xx response to an HTTP/1.0 client." This rule reports a response whose status falls in `100..=199` answering a request whose version is exactly `HTTP/1.0`.

**The subject is the class, not a status code.** Every member is reported — `100 (Continue)`, `101 (Switching Protocols)`, `102`, `103 (Early Hints)`, and any code in the range a future document defines — because the sentence names the range and not its members. The entry was previously reported only for `103`, from inside a rule scoped to that status, so a `100` answering an HTTP/1.0 request drew nothing.

**Both digits are the gate, and it is the request's version.** HTTP/1.1 is the version that defines `1xx`, so the minor digit is the whole difference; and the sentence names the *client*, because it is the client that has no way to place an interim response. A `1xx` in an HTTP/1.1, HTTP/2 or HTTP/3 exchange is ordinary and is not reported.

**A `101` is reported here rather than as `status_101_unsolicited`.** That entry's HTTP/1.0 arm rested on §7.8 — "A server that receives an Upgrade header field in an HTTP/1.0 request MUST ignore that Upgrade field" — which binds what a server does with a *field*, and is why the entry is `_unsolicited` rather than `_forbidden` and carries no keyword. §15.2 prohibits the message itself. `status_101_switching_protocols` now declines an HTTP/1.0 request rather than reporting one, so such a response draws one finding and not two; the two arms it keeps, HTTP/2 and HTTP/3, rest on sections that withhold a definition rather than state a prohibition.

**Nothing here reads a field.** Whether an interim response was recorded where the single final response should be is `status_103_early_hints_before_final`'s finding, and whether a `1xx` carries content, a trailer section, a `Content-Length` or a `Transfer-Encoding` is `no_body_for_1xx_204_304`'s.

## Violations

- [status_1xx_forbidden](../violations/status_1xx_forbidden.md) — An interim response answers a client whose version has none

## Specifications

- [RFC 9110 §15.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.2): Informational 1xx — the class is interim, such a response is terminated by the end of the header section and cannot contain content or trailers, and a server must not send one to an HTTP/1.0 client, which defined no 1xx status codes
- [RFC 9110 §15](https://www.rfc-editor.org/rfc/rfc9110.html#section-15): What the class is: a request's interim responses are the 1xx ones, and exactly one final response follows them — the definition the range in this rule comes from
- [RFC 9110 §7.8](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.8): The other sentence about an HTTP/1.0 client and an upgrade: a server MUST ignore an Upgrade field in such a request. It binds the field rather than the status code, which is why the 101 is reported here on §15.2 and not there on this

## Configuration

```toml
[rules.status_1xx_vs_request_version]
enabled = true
```

## Examples

### ✅ Good — the client speaks HTTP/1.1, which is the version that defines the class

```http
> POST /upload HTTP/1.1
> Expect: 100-continue

< 100 Continue
```

### ❌ Bad — HTTP/1.0 defined no 1xx status codes, so this client has no way to place the response and reads it as the final one

```http
> POST /upload HTTP/1.0
> Expect: 100-continue

< 100 Continue
```

### ❌ Bad — the same sentence, and the member another entry used to answer for on §7.8's weaker one

```http
> GET /chat HTTP/1.0
> Upgrade: websocket

< 101 Switching Protocols
< Upgrade: websocket
```
