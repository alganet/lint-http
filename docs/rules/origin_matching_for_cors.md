<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Origin Matching for CORS Responses

## Description

When a server responds to a cross-origin request the `Access-Control-Allow-Origin`
header must either repeat the request's `Origin` value or use the wildcard `*`.
Furthermore, the wildcard may **not** be used in conjunction with credentials
(`Access-Control-Allow-Credentials: true`).

This rule looks at transactions where the client supplied an `Origin` header
and the server returned an `Access-Control-Allow-Origin` header.  It
validates that the header set is semantically consistent with the request
origin and enforces the credential restriction on `*`.  If the request's
`Origin` value is syntactically invalid the rule also raises a violation.

This check applies to server responses (RuleScope::Server).

## Violations

- [access_control_allow_origin_conflicting](../violations/access_control_allow_origin_conflicting.md) — Access-Control-Allow-Origin echoes an origin that did not ask
- [access_control_allow_origin_credentials_conflicting](../violations/access_control_allow_origin_credentials_conflicting.md) — The wildcard origin sits on a response that also allows credentials
- [access_control_allow_origin_malformed](../violations/access_control_allow_origin_malformed.md) — Access-Control-Allow-Origin states a value that is none of `*`, `null` and a serialized origin
- [field_line_duplicated](../violations/field_line_duplicated.md) — A field is written on more lines than its definition allows
- [origin_malformed](../violations/origin_malformed.md) — An Origin derives from neither null nor a serialized origin
- [origin_path_forbidden](../violations/origin_path_forbidden.md) — An Origin names a path the production has no component for
- [uri_character_forbidden](../violations/uri_character_forbidden.md) — Value holds a character no URI is written with
- [uri_scheme_character_forbidden](../violations/uri_scheme_character_forbidden.md) — URI scheme holds a character outside letters, digits, '+', '-' and '.'
- [uri_scheme_empty](../violations/uri_scheme_empty.md) — URI scheme is empty
- [uri_scheme_leading_letter_missing](../violations/uri_scheme_leading_letter_missing.md) — URI scheme does not begin with a letter

## Specifications

- [RFC 6454](https://www.rfc-editor.org/rfc/rfc6454.html): The Web Origin Concept
- [RFC 6454 §7.1](https://www.rfc-editor.org/rfc/rfc6454.html#section-7.1): Origin header field syntax — `origin-list-or-null` is the literal `null` or a list of `serialized-origin`, and a `serialized-origin` is a scheme, `://`, a host and an optional port, with no path component
- [Fetch §3.3.3](https://fetch.spec.whatwg.org/#http-access-control-allow-origin): `Access-Control-Allow-Origin` carries one value: an echoed origin, `null`, or `*`
- [Fetch §4.10](https://fetch.spec.whatwg.org/#concept-cors-check): Fetch CORS check — `*` succeeds only where the request's credentials mode is not `include`, and every other value is compared against the byte-serialized request origin
- [MDN Access-Control-Allow-Origin](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Origin): Access-Control-Allow-Origin
- [RFC 3986 §2](https://www.rfc-editor.org/rfc/rfc3986.html#section-2): Characters — the limited set a URI is composed from, every other octet being percent-encoded before the reference is formed
- [RFC 3986 §3.1](https://www.rfc-editor.org/rfc/rfc3986.html#section-3.1): Scheme — `scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`, the name before the first colon
- [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3): Field Order — a sender MUST NOT write multiple field lines of one name, in the headers or the trailers, unless at least one alternative of the field's definition allows the lines to be recombined as a comma-separated list

## Configuration

```toml
[rules.origin_matching_for_cors]
enabled = true
```

## Examples

### ✅ Good (exact echo)

```http
GET /foo HTTP/1.1
Host: example.com
Origin: https://example.org

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://example.org
```

### ✅ Good (wildcard, no credentials)

```http
GET /foo HTTP/1.1
Host: example.com
Origin: https://example.org

HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
```

### ❌ Bad (`*` with credentials)

```http
GET /foo HTTP/1.1
Host: example.com
Origin: https://example.org

HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```

### ❌ Bad (mismatched origin)

```http
GET /foo HTTP/1.1
Host: example.com
Origin: https://foo.example

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://bar.example
```

### ❌ Bad (multiple header fields or list)

```http
GET /foo HTTP/1.1
Host: example.com
Origin: https://example.org

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://a, https://b
```

```http
GET /foo HTTP/1.1
Host: example.com
Origin: https://example.org

HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://a
Access-Control-Allow-Origin: https://b
```
