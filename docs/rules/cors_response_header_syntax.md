<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# CORS Response Header Syntax

## Description

Reads the four CORS response header values Fetch §3.3.4 gives a grammar and no rule read: `Access-Control-Expose-Headers = #field-name`, `Access-Control-Allow-Headers = #field-name`, `Access-Control-Allow-Methods = #method` and `Access-Control-Max-Age = delta-seconds`.

None of the four adds punctuation of its own, so every syntactic finding here is a statement about a production some other document owns, reported under that production's id: a member holding an octet `tchar` does not admit is the same defect a `Vary` field name or an `Allow` method has, and a `max-age` that is not `1*DIGIT` is the same defect an `Age` has. What stays the field's is what the tokens *mean*.

The three list-valued fields are `#`-lists, so a value with nothing on it is a legal zero-element list and draws nothing; an empty element *within* a list — a leading, trailing or doubled comma — is reported once for the line. `*` needs no special case: Fetch gives it a meaning of its own in these three fields and `tchar` admits it, so it is a `token` before it is a wildcard.

One finding here is not a grammar defect. A method in `Access-Control-Allow-Methods` written as a standardized name in another case — `get` for `GET` — parses perfectly and allows nothing, because Fetch matches it against the request's method byte-for-byte. Reporting it needs the `registered_methods` array, for the reason `request_method_token_valid` needs it: the convention is what makes a lowercase spelling recognisable as a mistake, and no rule may compile in a registry that grows by IETF Review.

What this rule does not decide: whether the fields should be present at all (`options_method_capabilities` reads that), whether `Access-Control-Allow-Origin` and `Access-Control-Allow-Credentials` agree (their own rules read those two of §3.3.4's productions), and whether a named header or method is one the resource actually has.

## Violations

- [delta_seconds_character_forbidden](../violations/delta_seconds_character_forbidden.md) — A time in seconds holds an octet DIGIT does not admit
- [delta_seconds_empty](../violations/delta_seconds_empty.md) — A time in seconds is stated with no digits
- [list_member_empty](../violations/list_member_empty.md) — List holds an empty element
- [method_case_invalid](../violations/method_case_invalid.md) — A method is a standardized name written in another case
- [token_character_forbidden](../violations/token_character_forbidden.md) — Token holds a character outside tchar
- [token_whitespace_or_control_forbidden](../violations/token_whitespace_or_control_forbidden.md) — Token holds whitespace or a control character

## Specifications

- [Fetch §3.3.4](https://fetch.spec.whatwg.org/#http-new-header-syntax): ABNF for the CORS protocol's header values. The four response fields read here — `Access-Control-Expose-Headers = #field-name`, `Access-Control-Allow-Headers = #field-name`, `Access-Control-Allow-Methods = #method` and `Access-Control-Max-Age = delta-seconds` — name productions three other documents define, and none of the four adds punctuation of its own
- [Fetch §3.3.3](https://fetch.spec.whatwg.org/#http-responses): Which of these fields a CORS response may carry, and that `*` counts as a wildcard in the three list-valued ones for requests without credentials — which needs no arm in the reading, `tchar` admitting the asterisk
- [RFC 9110 §5.6.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1): The list construct — `1#element => element *( OWS "," OWS element )`, and the sender's MUST NOT against an empty element
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): Tokens — `token = 1*tchar`, and the fifteen punctuation marks besides the digits and letters that `tchar` admits
- [RFC 9110 §9.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.1): `method = token`, the token's case-sensitivity, the convention that standardized methods are defined in all-uppercase US-ASCII letters, and the 501 an origin server gives an unrecognized method
- [RFC 9111 §1.2.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-1.2.2): `delta-seconds = 1*DIGIT` — the production every field carrying a time in seconds writes its value in, and the clamp that makes an over-long run of digits conforming

## Configuration

```toml
[rules.cors_response_header_syntax]
enabled = true
# The standardized method names this deployment expects to see spelled the way their
# definitions spell them, used only by the `Access-Control-Allow-Methods` reading.
# Fetch compares a method in that field against the request's method byte-for-byte,
# so `get` allows nothing — but `get` is a perfectly good `token`, and only a list of
# names makes the lowercase spelling recognisable as a mistake rather than as somebody's
# private method. The same array `request_method_token_valid` takes, for the same reason.
registered_methods = ["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"]
```

## Examples

### ✅ Good

```http
HTTP/1.1 204 No Content
Access-Control-Allow-Methods: GET, POST
Access-Control-Allow-Headers: Content-Type
Access-Control-Max-Age: 86400
```

### ✅ Good a `#`-list derives the empty list, and `tchar` admits the asterisk

```http
HTTP/1.1 204 No Content
Access-Control-Expose-Headers: *
```

### ❌ Bad `#field-name` is comma-separated, so this is one member holding a space and it exposes nothing

```http
HTTP/1.1 200 OK
Access-Control-Expose-Headers: Content-Length Content-Range
```

### ❌ Bad a field-name is a token, and `:` is no tchar

```http
HTTP/1.1 204 No Content
Access-Control-Allow-Headers: Content-Type:
```

### ❌ Bad an empty element within the list

```http
HTTP/1.1 204 No Content
Access-Control-Allow-Methods: GET,,POST
```

### ❌ Bad the method token is case-sensitive, so this allows nothing

```http
HTTP/1.1 204 No Content
Access-Control-Allow-Methods: get, POST
```

### ❌ Bad `delta-seconds` is `1*DIGIT` and admits no sign

```http
HTTP/1.1 204 No Content
Access-Control-Max-Age: -1
```
