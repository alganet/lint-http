<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Strict Transport Security Valid

## Description

The `Strict-Transport-Security` response header signals HSTS policies. This rule ensures responses include the required `max-age` directive (a non-negative integer) and that optional directives `includeSubDomains` and `preload` are present without values. Unknown directives are accepted but any value must be a `token` or `quoted-string`. The value is read as the octets the sender wrote, so an octet outside the `token` alphabet is reported where it lands rather than as an encoding verdict about the whole field.\n\n**The field may be written only once.** RFC 6797 §7.1: *"If an STS header field is included, the HSTS Host MUST include only one such header field"* — and §6.1's directives are semicolon-separated, so no alternative of the production is a comma-separated list and RFC 9110 §5.3's exception does not reach the field. What a recipient does about it is not §5.2's recombination: §8.1 has a UA *"process only the first such header field"*, so a second line is discarded rather than joined, and the policy in force is whichever one the server emitted first. The finding names every line, because which one is first is the whole answer.

## Violations

- [delta_seconds_character_forbidden](../violations/delta_seconds_character_forbidden.md) — A time in seconds holds an octet DIGIT does not admit
- [delta_seconds_empty](../violations/delta_seconds_empty.md) — A time in seconds is stated with no digits
- [field_line_duplicated](../violations/field_line_duplicated.md) — A field is written on more lines than its definition allows
- [quoted_pair_malformed](../violations/quoted_pair_malformed.md) — Escape is not a quoted-pair
- [quoted_string_control_character_forbidden](../violations/quoted_string_control_character_forbidden.md) — Quoted-string holds a control character
- [quoted_string_delimiter_missing](../violations/quoted_string_delimiter_missing.md) — Quoted-string is missing one of its DQUOTEs
- [quoted_string_quote_escape_missing](../violations/quoted_string_quote_escape_missing.md) — Quoted-string holds an unescaped DQUOTE
- [strict_transport_security_directive_duplicated](../violations/strict_transport_security_directive_duplicated.md) — A directive is written more than once in one policy
- [strict_transport_security_directive_empty](../violations/strict_transport_security_directive_empty.md) — The policy holds a separator with no directive
- [strict_transport_security_directive_value_forbidden](../violations/strict_transport_security_directive_value_forbidden.md) — A valueless directive is written with a value
- [strict_transport_security_directive_value_missing](../violations/strict_transport_security_directive_value_missing.md) — A directive that requires a value carries none
- [strict_transport_security_empty](../violations/strict_transport_security_empty.md) — The policy is written with nothing in it
- [strict_transport_security_max_age_missing](../violations/strict_transport_security_max_age_missing.md) — The policy states no max-age
- [token_character_forbidden](../violations/token_character_forbidden.md) — Token holds a character outside tchar
- [token_empty](../violations/token_empty.md) — Token is written with no characters in it
- [token_whitespace_or_control_forbidden](../violations/token_whitespace_or_control_forbidden.md) — Token holds whitespace or a control character

## Specifications

- [RFC 6797 §6.1](https://www.rfc-editor.org/rfc/rfc6797.html#section-6.1): Strict-Transport-Security header
- [RFC 6797 §6.1.1](https://www.rfc-editor.org/rfc/rfc6797.html#section-6.1.1): The max-age Directive
- [RFC 6797 §6.1.2](https://www.rfc-editor.org/rfc/rfc6797.html#section-6.1.2): The includeSubDomains Directive
- [RFC 6797 §7.1](https://www.rfc-editor.org/rfc/rfc6797.html#section-7.1): HTTP-over-Secure-Transport Request Type — the sentence obliging an HSTS Host that includes the field to include only one of it
- [RFC 6797 §8.1](https://www.rfc-editor.org/rfc/rfc6797.html#section-8.1): Strict-Transport-Security Response Header Field Processing — the UA processes only the first of several STS header fields
- [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3): Field Order — a sender MUST NOT write multiple field lines of one name, in the headers or the trailers, unless at least one alternative of the field's definition allows the lines to be recombined as a comma-separated list
- [RFC 9111 §1.2.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-1.2.2): `delta-seconds = 1*DIGIT` — the production every field carrying a time in seconds writes its value in, and the clamp that makes an over-long run of digits conforming
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): Tokens — `token = 1*tchar`, and the fifteen punctuation marks besides the digits and letters that `tchar` admits
- [RFC 9110 §5.6.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.4): `quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE` — the two delimiters, the class between them, and the backslash escape

## Configuration

```toml
[rules.strict_transport_security_valid]
enabled = true
```

## Examples

### ✅ Good

```http
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

```http
Strict-Transport-Security: max-age=0
```

### ✅ Good — the quoted-string form § 6.1.1 unescapes before reading

```http
Strict-Transport-Security: max-age="63072000"
```

### ❌ Bad — missing `max-age`

```http
Strict-Transport-Security: includeSubDomains
```

### ❌ Bad — `max-age` not numeric

```http
Strict-Transport-Security: max-age=abc
```

### ❌ Bad — `includeSubDomains` must not have a value

```http
Strict-Transport-Security: max-age=63072000; includeSubDomains=1
```

### ❌ Bad — a trailing `;` opens a directive the sender never wrote

```http
Strict-Transport-Security: max-age=15552000;
```

### ❌ Bad — two policies, of which a UA reads the ten-minute one and discards the other

```http
HTTP/1.1 200 OK
Strict-Transport-Security: max-age=600
Strict-Transport-Security: max-age=15724800; includeSubDomains
```
