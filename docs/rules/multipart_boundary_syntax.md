<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Multipart Boundary Syntax

## Description

Check that a `Content-Type` naming a `multipart/*` media type carries a `boundary` parameter, and that the parameter's value is one RFC 2046 §5.1.1 allows: 1 to 70 characters drawn from `bchars` — letters, digits, `'`, `(`, `)`, `+`, `_`, `,`, `-`, `.`, `/`, `:`, `=`, `?` and space — and not ending in a space. A quoted value is judged after unescaping, since the quoted and unquoted forms name the same value.

**RFC 9110 §8.3.3 is why a MIME rule applies to HTTP at all:** it adopts §5.1.1 wholesale for every multipart type and says the boundary parameter is part of the media type value. The two multipart types HTTP itself deals in run in opposite directions — `multipart/form-data` in requests, `multipart/byteranges` in 206 responses — which is why both are checked.

**Quoting is often not optional.** Seven characters `bchars` permits (`(`, `)`, `,`, `/`, `:`, `=`, `?`) and space are not `tchar`, so a boundary using any of them can only be transmitted inside a quoted-string; unquoted, it is reported as an invalid token character. RFC 2046 warns implementors of exactly this.

**Scope:** this rule reports only on the boundary parameter. A `Content-Type` that does not parse as a `media-type`, and the presence of more than one `Content-Type` field line, are both `content_type_valid`'s findings. Every `Content-Type` line in the header section of each message is read, since recipients differ over which one they act on; trailers are not read, as a `Content-Type` there is a framing question rather than a boundary one.

**What is not checked:** this is a header rule, so the rest of RFC 2046 §5.1.1 — that the delimiter must not appear inside the encapsulated material, and that nested multipart entities must use different boundaries — is outside it. Whether the declared boundary actually delimits the body is `multipart_content_type_and_body_consistent`'s question. A conforming boundary also says nothing about message length: RFC 9110 §8.3.3 is explicit that HTTP framing does not use the boundary.

**Quoting that never closes is declined, not guessed at.** After a stray `"` no separator can be trusted, so `multipart/mixed; foo="unterminated; boundary=abc` is not reported as missing a boundary — whether that text is a parameter is precisely what the broken quoting makes unknowable, and the malformed value is `content_type_valid`'s finding. This applies only to the *absence* claim: a boundary the scan did find is still judged, so `boundary="unfinished` is reported as the malformed quoted-string it is.

**Whitespace beside the `=` is read through here and reported elsewhere.** RFC 9110 §5.6.6 forbids it, and this rule trims it before judging the boundary, so `boundary= abc` names the boundary `abc` — the value a recipient would use, and the one worth judging. The octet itself is `content_type_valid`'s finding, and that rule no longer passes over it.

## Violations

- [boundary_character_forbidden](../violations/boundary_character_forbidden.md) — Boundary holds a character outside the delimiter set
- [boundary_length_invalid](../violations/boundary_length_invalid.md) — Boundary is empty or longer than seventy characters
- [boundary_missing](../violations/boundary_missing.md) — A multipart media type carries no boundary parameter
- [boundary_trailing_space_forbidden](../violations/boundary_trailing_space_forbidden.md) — Boundary ends with a space
- [parameter_value_empty](../violations/parameter_value_empty.md) — Parameter is written with no value after its '='
- [quoted_pair_malformed](../violations/quoted_pair_malformed.md) — Escape is not a quoted-pair
- [quoted_string_control_character_forbidden](../violations/quoted_string_control_character_forbidden.md) — Quoted-string holds a control character
- [quoted_string_delimiter_missing](../violations/quoted_string_delimiter_missing.md) — Quoted-string is missing one of its DQUOTEs
- [quoted_string_quote_escape_missing](../violations/quoted_string_quote_escape_missing.md) — Quoted-string holds an unescaped DQUOTE
- [token_character_forbidden](../violations/token_character_forbidden.md) — Token holds a character outside tchar
- [token_whitespace_or_control_forbidden](../violations/token_whitespace_or_control_forbidden.md) — Token holds whitespace or a control character

## Specifications

- [RFC 2046 §5.1.1](https://www.rfc-editor.org/rfc/rfc2046.html#section-5.1.1): Multipart common syntax: the required `boundary` parameter, the `boundary`/`bchars`/`bcharsnospace` grammar, the 1-to-70-character limit and the ban on a trailing space, and the warning that a boundary often has to be quoted
- [RFC 9110 §8.3.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.3): Multipart Types: where HTTP adopts RFC 2046 §5.1.1 and makes the boundary part of the media type value. It also says HTTP framing does not use the boundary as a length indicator, so nothing here is a framing check
- [RFC 9110 §5.6.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.6): Parameters — `parameters = *( OWS ";" OWS [ parameter ] )`, the `name=value` pair inside it with neither half optional, and the bracketing that leaves a trailing `;` conforming
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): Tokens — `token = 1*tchar`, and the fifteen punctuation marks besides the digits and letters that `tchar` admits
- [RFC 9110 §5.6.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.4): `quoted-string = DQUOTE *( qdtext / quoted-pair ) DQUOTE` — the two delimiters, the class between them, and the backslash escape
- [RFC 9110 §8.3.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.1): Media Type: the case-insensitivity of `type`, which is what scopes this rule to `multipart`

## Configuration

```toml
[rules.multipart_boundary_syntax]
enabled = true
```

## Examples

### ✅ Good

```http
Content-Type: multipart/mixed; boundary=gc0p4Jq0M2Yt08j34c0p
```

### ✅ Good (a colon is a bchars, so quoting makes it transmissible)

```http
Content-Type: multipart/mixed; boundary="gc0pJq0M:08jU534c0p"
```

### ✅ Good (space is a bchars everywhere but the last position)

```http
Content-Type: multipart/mixed; boundary="simple boundary"
```

### ❌ Bad (no boundary parameter)

```http
Content-Type: multipart/mixed
```

### ❌ Bad (no boundary parameter: the text is inside another value)

```http
Content-Type: multipart/mixed; foo="a; boundary=abc; b=1"
```

### ❌ Bad (nothing after the "=" is not a parameter-value)

```http
Content-Type: multipart/mixed; boundary=
```

### ❌ Bad (empty after unquoting)

```http
Content-Type: multipart/mixed; boundary=""
```

### ❌ Bad (must not end in white space)

```http
Content-Type: multipart/mixed; boundary="abc "
```

### ❌ Bad (a colon is not a tchar, so it must be quoted)

```http
Content-Type: multipart/mixed; boundary=gc0pJq0M:08jU534c0p
```
