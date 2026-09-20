<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# CORS Request Header Syntax

## Description

Reads the two CORS request header values Fetch §3.3.4 gives a grammar and no rule read: `Access-Control-Request-Method = method` and `Access-Control-Request-Headers = 1#field-name`.

Neither field adds punctuation of its own, so every syntactic finding here is a statement about a production RFC 9110 owns, reported under that production's id: a value holding an octet `tchar` does not admit is the same defect a `Vary` field name or an `Allow` method has.

**`Access-Control-Request-Headers` is `1#field-name`, not `#field-name`.** The `1#` has a floor, so a header line written with nothing on it states no header name and is reported — where the three list-valued *response* fields of the same ABNF block are plain `#element`, derive the empty list, and are silent on the same shape. An empty element *within* the list — a leading, trailing or doubled comma — is reported once for the line in both.

One finding here is not a grammar defect. A method in `Access-Control-Request-Method` written as a standardized name in another case — `get` for `GET` — parses perfectly and announces a method nothing defines, because the preflight's method is compared byte-for-byte. Reporting it needs the `registered_methods` array, for the reason `request_method_token_valid` needs it: the convention is what makes a lowercase spelling recognisable as a mistake, and no rule may compile in a registry that grows by IETF Review.

What this rule does not decide: whether a preflight should have been sent at all, whether the server's answer matches what was asked for (`options_method_capabilities` and the `Access-Control-Allow-*` rules read that), and whether the named headers are ones the request would actually carry.

## Violations

- [list_member_empty](../violations/list_member_empty.md) — List holds an empty element
- [list_member_missing](../violations/list_member_missing.md) — List with a one-element floor holds no element
- [method_case_invalid](../violations/method_case_invalid.md) — A method is a standardized name written in another case
- [token_character_forbidden](../violations/token_character_forbidden.md) — Token holds a character outside tchar
- [token_empty](../violations/token_empty.md) — Token is written with no characters in it
- [token_whitespace_or_control_forbidden](../violations/token_whitespace_or_control_forbidden.md) — Token holds whitespace or a control character

## Specifications

- [Fetch §3.3.4](https://fetch.spec.whatwg.org/#http-new-header-syntax): ABNF for the CORS protocol's header values. The two request fields read here — `Access-Control-Request-Method = method` and `Access-Control-Request-Headers = 1#field-name` — name productions RFC 9110 defines, and the `1#` is the one place this block's two list spellings differ
- [Fetch §3.3.2](https://fetch.spec.whatwg.org/#cors-preflight-request): The CORS-preflight request and the two headers it carries: the method a future request might use, and the header names it might carry
- [RFC 9110 §5.6.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1): The list construct — `1#element => element *( OWS "," OWS element )`, and the sender's MUST NOT against an empty element
- [RFC 9110 §5.6.1.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.2): The values a `1#element` production does not generate — the empty value among them — beside the recipient's instruction to ignore empty elements
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): Tokens — `token = 1*tchar`, and the fifteen punctuation marks besides the digits and letters that `tchar` admits
- [RFC 9110 §9.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.1): `method = token`, the token's case-sensitivity, the convention that standardized methods are defined in all-uppercase US-ASCII letters, and the 501 an origin server gives an unrecognized method

## Configuration

```toml
[rules.cors_request_header_syntax]
enabled = true
# The standardized method names this deployment expects to see spelled the way their
# definitions spell them, used only by the `Access-Control-Request-Method` reading.
# The preflight names a method a later request will use, and that comparison is
# byte-for-byte — so `get` announces a method nothing defines. But `get` is a perfectly
# good `token`, and only a list of names makes the lowercase spelling recognisable as a
# mistake rather than as somebody's private method. The same array
# `request_method_token_valid` takes, for the same reason.
registered_methods = ["GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"]
```

## Examples

### ✅ Good

```http
OPTIONS /r HTTP/1.1
Host: example.com
Origin: https://app.example
Access-Control-Request-Method: POST
Access-Control-Request-Headers: Content-Type
```

### ❌ Bad `1#field-name` has a floor, so a line with nothing on it states no header name

```http
OPTIONS /r HTTP/1.1
Host: example.com
Origin: https://app.example
Access-Control-Request-Method: POST
Access-Control-Request-Headers:
```

### ❌ Bad `1#field-name` is comma-separated, so this is one member holding a space

```http
OPTIONS /r HTTP/1.1
Host: example.com
Origin: https://app.example
Access-Control-Request-Method: POST
Access-Control-Request-Headers: Content-Type X-Foo
```

### ❌ Bad a method is a token, and `(` is no tchar

```http
OPTIONS /r HTTP/1.1
Host: example.com
Origin: https://app.example
Access-Control-Request-Method: PO(ST
```

### ❌ Bad the method token is case-sensitive, so this announces a method nothing defines

```http
OPTIONS /r HTTP/1.1
Host: example.com
Origin: https://app.example
Access-Control-Request-Method: post
```
