<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Charset Iana Registered

## Description

If a `Content-Type` header carries a `charset` parameter, this rule checks the name against an allowlist you configure. It also reports an empty `charset`, a malformed quoted-string, and characters that do not belong in the name.

**It does not consult the IANA registry**, despite the rule's name: there is no lookup, and a charset is "registered" as far as this rule is concerned exactly when your `allowed` array covers it. RFC 9110 §8.3.2 says charset names *ought to* be registered, which is the motivation for the rule, but the check itself is your policy. Matching is case-insensitive, as §8.3.2 requires, and a quoted value is compared after unescaping, since the quoted and unquoted forms are equivalent.

**`token` is not the charset production.** An unquoted name is checked against `token`, while a charset name follows `mime-charset` (RFC 2978 §2.3). The two sets are *incomparable*: `mime-charset` admits `{` and `}` that `token` rejects, and `token` admits `*`, `.` and `|` that `mime-charset` rejects — so `charset=utf.8` reaches the allowlist rather than being called malformed. Neither direction changes a verdict: RFC 9110 §8.3.2 says no registered charset name uses braces, and a name carrying `.` or `*` is reported by the allowlist check if it is not configured. Only the wording of the finding differs.

**Scope:** this rule reports only on charsets. A `Content-Type` that does not parse as a `media-type`, and the presence of more than one `Content-Type` field line, are both `message_content_type_well_formed`'s findings. It reads every `Content-Type` line in the header section of each message; trailers are not read, since a `Content-Type` there is malformed framing rather than a charset question.

**One silence worth knowing about:** an unbalanced quote in an *earlier* parameter swallows the rest of the value, so `boundary="unterminated; charset=bogus` yields no charset finding here. The value is malformed and `message_content_type_well_formed` reports it; there is genuinely no parameter list left to read once the quoting breaks.

## Specifications

- [RFC 9110 §8.3.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.2): Charset: what the parameter means, that names are matched case-insensitively, and the "ought to be registered" guidance that motivates this rule — guidance, not a requirement, and not something this rule verifies
- [RFC 9110 §5.6.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.6): Parameters: case-insensitive names, and `parameter-value = ( token / quoted-string )` — the fork this rule takes on the value
- [RFC 2978 §2.3](https://www.rfc-editor.org/rfc/rfc2978.html#section-2.3): `mime-charset`, the production a charset name actually follows. It and `token` are incomparable — `{`/`}` on one side, `*`/`.`/`|` on the other — so checking `token` is stricter in one direction and looser in the other, and neither direction changes a verdict
- [IANA Character Sets](https://www.iana.org/assignments/character-sets/character-sets.xhtml): The registry this rule is named after but does not read; the configured `allowed` array stands in for it

## Configuration

```toml
[rules.message_charset_iana_registered]
enabled = true
severity = "warn"
allowed = ["utf-8", "iso-8859-1", "us-ascii"]
```

## Examples

### ✅ Good

```http
GET / HTTP/1.1
Host: example.com
Content-Type: text/plain; charset=utf-8
```

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset="UTF-8"
X-Content-Type-Options: nosniff

<html>...</html>
```

### ❌ Bad

```http
HTTP/1.1 200 OK
Content-Type: text/plain; charset=unknown-charset
```

```http
HTTP/1.1 200 OK
Content-Type: text/plain; charset="unfinished
```
