<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# A Location that refers to nothing

## Description

RFC 9110 §10.2.2 gives the `Location` header field a referent twice — the primary resource created, on a `201 Created`, and the preferred target resource to redirect to, on a `3xx (Redirection)` response. This rule reports a response on any other status that carries the field, because there the value refers to nothing the specification names.

**This is advice, not a violation.** §10.2.2 says the field is *"used in some responses"* and then says which; it does not forbid the rest, and no other sentence in RFC 9110 does either. A `202 Accepted` carrying a `Location` for a status monitor is the common case — §15.3.3 asks the 202's *content* to point at that monitor, so the field is carrying a meaning by convention rather than by specification. What the finding buys is that the convention is visible.

**The whole 3xx class is exempt, not a list of redirect codes.** The licensing sentence names `3xx (Redirection)` responses, so `304 Not Modified`, the deprecated `305 Use Proxy`, the reserved `306`, and any 3xx that is not registered at all are all exempt. §15.4 says a user agent MAY follow a provided `Location` *"even if the specific status code is not understood"*, and §15 requires a client to treat an unrecognized status as the `x00` of its class — so an unregistered 3xx is a `300` to every conforming recipient and carries the same relationship to the field. §15.4.5's `SHOULD NOT` on a 304 is about representation metadata (§8); `Location` is a response context field (§10.2) and is not reached by it.

**Only presence is read.** Whether the value is a usable `URI-reference`, whether it is empty, and whether the response sent several `Location` field lines are `server_location_header_uri_valid`'s questions. A `301` or `302` that carries *no* `Location` is `server_response_location_on_redirect`'s. Whether a `201` ought to carry one is `post_creates_resource`'s, because the sentence that asks for it (§9.3.3) is about `POST`.

## Specifications

- [RFC 9110 §10.2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.2): `Location = URI-reference`; the value's referent is defined for 201 (Created) and for 3xx (Redirection) responses, and for no other status
- [RFC 9110 §15.3.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.2): 201 Created: the primary resource created is identified by a Location field or, if none is received, by the target URI — a description, not a request for the field
- [RFC 9110 §15.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4): Redirection 3xx: a provided Location may be followed automatically even where the user agent does not understand the specific status code
- [RFC 9110 §15](https://www.rfc-editor.org/rfc/rfc9110.html#section-15): An unrecognized status code is equivalent to the x00 of its class, which is what makes 3xx a class here rather than a list of six codes

## Configuration

```toml
[rules.server_redirect_status_and_location_validity]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Content-Type: text/plain

Hello
```

### ✅ Good (redirect)

```http
HTTP/1.1 302 Found
Location: /new
```

### ✅ Good (the referent is defined for the 3xx class)

```http
HTTP/1.1 304 Not Modified
ETag: "xyzzy"
Location: /alternate
```

### ✅ Good (the resource the request created)

```http
HTTP/1.1 201 Created
Location: /widgets/123
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Location: /unexpected
```

### ❌ Bad (a 202's status monitor is named by its content)

```http
HTTP/1.1 202 Accepted
Location: /jobs/42
```
