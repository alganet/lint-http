<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Cookie Pair Valid

## Description

This rule measures the `Cookie` request header against RFC 6265 §4.2.1's grammar: `cookie-string = cookie-pair *( ";" SP cookie-pair )`, `cookie-pair = cookie-name "=" cookie-value`, `cookie-name = token`, `cookie-value = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )`. Each field line is split on `;` into cookie-pairs, and each pair is judged on its own: a segment with no `=` at all, a `cookie-name` that is not a `token` (reported under the same shared id `Set-Cookie`'s cookie-name already uses), and a `cookie-value` carrying an octet outside `cookie-octet` — a comma, a semicolon, a backslash, a bare double-quote, whitespace, a control character, or anything above %x7E, unless the whole value is wrapped in a matching pair of double quotes, which `cookie-octet` also allows. §4.2.1 states no keyword of its own about the value a sender constructs — it only describes what a user agent sends given that the server and the user agent already conform — so what makes a non-conforming value reportable is RFC 9110 §2.2's blanket MUST NOT on generating a protocol element outside its grammar. A `Cookie` header split across several field lines (RFC 9113 §8.2.3, HTTP/2 and HTTP/3) is judged one line at a time, since each line is independently a well-formed `cookie-string`. A stray empty segment between two `;`s (`a=1;;b=2`) is tolerated rather than reported, matching this crate's treatment of `Set-Cookie`'s attribute list. Whether a request should carry a `Cookie` field at all, and whether its value matches what was last set, are different questions this rule does not ask.

## Violations

- [cookie_pair_equals_missing](../violations/cookie_pair_equals_missing.md) — A Cookie pair is written without its '='
- [cookie_value_character_forbidden](../violations/cookie_value_character_forbidden.md) — Cookie value holds a character outside cookie-octet
- [token_character_forbidden](../violations/token_character_forbidden.md) — Token holds a character outside tchar
- [token_empty](../violations/token_empty.md) — Token is written with no characters in it
- [token_whitespace_or_control_forbidden](../violations/token_whitespace_or_control_forbidden.md) — Token holds whitespace or a control character

## Specifications

- [RFC 6265 §4.2.1](https://www.rfc-editor.org/rfc/rfc6265.html#section-4.2.1): Cookie request header syntax — cookie-header and cookie-string; cookie-pair itself is imported from § 4.1.1
- [RFC 6265 §4.1.1](https://www.rfc-editor.org/rfc/rfc6265.html#section-4.1.1): Set-Cookie syntax — servers SHOULD NOT send a non-conforming Set-Cookie; the `cookie-av` list, where each attribute is written with or without a value, and the `path-value` that excludes control characters and `;`
- [RFC 9110 §2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2): The MUST NOT that makes a value outside the field's ABNF a finding, since §4.2.1 states no keyword of its own
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): Tokens — `token = 1*tchar`, and the fifteen punctuation marks besides the digits and letters that `tchar` admits

## Configuration

```toml
[rules.cookie_pair_valid]
enabled = true
```

## Examples

### ✅ Good (the section's own example)

```http
GET / HTTP/1.1
Cookie: SID=31d4d96e407aad42
```

### ✅ Good (more than one pair)

```http
GET / HTTP/1.1
Cookie: SID=31d4d96e407aad42; lang=en-US
```

### ✅ Good (a quoted cookie-value)

```http
GET / HTTP/1.1
Cookie: SID="31d4d96e407aad42"
```

### ❌ Bad (no '=' in a pair)

```http
GET / HTTP/1.1
Cookie: SID
```

### ❌ Bad (cookie-name is not a token)

```http
GET / HTTP/1.1
Cookie: S ID=31d4d96e407aad42
```

### ❌ Bad (a comma is not a cookie-octet)

```http
GET / HTTP/1.1
Cookie: SID=31d4,d96e
```
