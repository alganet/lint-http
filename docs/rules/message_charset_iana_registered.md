<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Charset Iana Registered

## Description

If a `Content-Type` header carries a `charset` parameter, this rule checks the name against an allowlist you configure. It also reports an empty `charset`, a malformed quoted-string, and characters that do not belong in the name.

**It does not consult the IANA registry**, despite the rule's name: there is no lookup, and a charset is "registered" as far as this rule is concerned exactly when your `allowed` array covers it. RFC 9110 §8.3.2 says charset names *ought to* be registered, which is the motivation for the rule, but the check itself is your policy. Matching is case-insensitive, as §8.3.2 requires, and a quoted value is compared after unescaping, since the quoted and unquoted forms are equivalent.

**Known narrowing:** an unquoted name is checked against `token`, while the charset production (`mime-charset`, RFC 2978 §2.3) also admits `{` and `}`. RFC 9110 §8.3.2 notes both facts and adds that no registered charset name uses braces — and since an unrecognized name is reported anyway, this changes the wording of the finding rather than whether there is one.

**Scope:** a `Content-Type` that does not parse as a `media-type` is skipped here; that is `message_content_type_well_formed`'s finding, as is the presence of more than one `Content-Type` field line. This rule reads every line and reports only on the charsets it finds.

## Specifications

- [RFC 9110 §8.3.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.2): Charset: what the parameter means, that names are matched case-insensitively, and the "ought to be registered" guidance that motivates this rule — guidance, not a requirement, and not something this rule verifies
- [RFC 9110 §5.6.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.6): Parameters: case-insensitive names, and `parameter-value = ( token / quoted-string )` — the fork this rule takes on the value
- [RFC 2978 §2.3](https://www.rfc-editor.org/rfc/rfc2978.html#section-2.3): `mime-charset`, the production a charset name actually follows. It admits `{` and `}`, which `token` does not; this rule checks `token`, a narrowing RFC 9110 §8.3.2 itself calls harmless
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
