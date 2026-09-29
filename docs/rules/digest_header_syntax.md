<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Digest Header Syntax

## Description

RFC 9530 obsoletes RFC 3230 and defines modern Integrity fields: `Content-Digest` (for message content), `Repr-Digest` (for representation data) and their preference counterparts `Want-Content-Digest` / `Want-Repr-Digest`. This rule validates:

- **Legacy** `Digest` (`alg=base64`) and `Want-Digest` (algorithms, each with an optional `;q=` weight) header syntax, and flags their use as obsoleted by RFC 9530.
- **New** RFC 9530 Integrity fields (`Content-Digest`, `Repr-Digest`) must follow the structured dictionary syntax (e.g., `sha-256=:BASE64:`) with byte sequences that decode as valid Base64. A member's parameters are not part of its value: RFC 9530 defines none and RFC 9651 gives every member room for them, so `sha-256=:BASE64:;x=1` is read as the digest it carries, and only a parameter that is not one is reported.
- **Integrity preference** fields (`Want-Content-Digest`, `Want-Repr-Digest`) use algorithm=weight pairs where weight is an integer in 0..=10.
- **Obsolete field**: presence of `Content-MD5` is flagged. It was removed from HTTP by RFC 7231 (not by RFC 9530, which does not mention it); prefer `Content-Digest`.

Algorithm names in the RFC 9530 fields are structured-field Dictionary keys and so must be lowercase (`sha-256`, not the `SHA-256` spelling used by the obsolete `Digest` field, whose algorithm token is case-insensitive).

`Content-Digest` and `Repr-Digest` are read in the **trailer section** as well as the header section, in either direction: RFC 9530 §2 and §3 each say the field "can be sent in a trailer section", which is where a digest computed while the content streams arrives. No other field here is granted the section, and one written there is `trailer_fields_valid`'s finding.

## Violations

- [base64_malformed](../violations/base64_malformed.md) — Value is not a base64 encoding
- [content_md5_obsolete](../violations/content_md5_obsolete.md) — Content-MD5 is a field HTTP removed
- [digest_equals_missing](../violations/digest_equals_missing.md) — Digest member is written without its '='
- [digest_field_obsolete](../violations/digest_field_obsolete.md) — Digest or Want-Digest is a field RFC 9530 retired
- [digest_member_empty](../violations/digest_member_empty.md) — Digest field writes a comma with no member beside it
- [digest_preference_invalid](../violations/digest_preference_invalid.md) — Want-Digest preference is outside the range 0 to 10
- [digest_preference_malformed](../violations/digest_preference_malformed.md) — Want-Digest preference is not an Integer
- [digest_value_empty](../violations/digest_value_empty.md) — Digest field member carries no digest
- [digest_value_malformed](../violations/digest_value_malformed.md) — Digest field member's value is not a Byte Sequence
- [qvalue_malformed](../violations/qvalue_malformed.md) — Weight is not a qvalue
- [structured_field_key_malformed](../violations/structured_field_key_malformed.md) — Structured field key is not a key production
- [structured_field_member_empty](../violations/structured_field_member_empty.md) — Structured field writes a comma with no member beside it
- [structured_field_value_malformed](../violations/structured_field_value_malformed.md) — Structured field value is none of the bare item types
- [token_character_forbidden](../violations/token_character_forbidden.md) — Token holds a character outside tchar
- [token_empty](../violations/token_empty.md) — Token is written with no characters in it
- [token_whitespace_or_control_forbidden](../violations/token_whitespace_or_control_forbidden.md) — Token holds whitespace or a control character
- [weight_duplicated](../violations/weight_duplicated.md) — Member carries more than one weight
- [weight_malformed](../violations/weight_malformed.md) — Something other than a weight follows the member's ';'
- [weight_missing](../violations/weight_missing.md) — Member writes the weight's ';' and no weight after it

## Specifications

- [RFC 9530 §2](https://www.rfc-editor.org/rfc/rfc9530.html#section-2): `Content-Digest`: a Dictionary keyed by hashing algorithm whose values are Byte Sequences
- [RFC 9530 §3](https://www.rfc-editor.org/rfc/rfc9530.html#section-3): `Repr-Digest`: the same syntax over representation data rather than message content
- [RFC 9530 §4](https://www.rfc-editor.org/rfc/rfc9530.html#section-4): `Want-Content-Digest` / `Want-Repr-Digest`: a Dictionary whose values are Integers in the range 0 to 10 inclusive
- [RFC 3230 §4.1.1](https://www.rfc-editor.org/rfc/rfc3230.html#section-4.1.1): Historical `Digest` / `Want-Digest`, obsoleted by RFC 9530: `digest-algorithm = token`, case-insensitive — which is why uppercase is valid there and not in the structured fields
- [RFC 3230 §4.3.1](https://www.rfc-editor.org/rfc/rfc3230.html#section-4.3.1): Historical `Want-Digest`, obsoleted by RFC 9530: `#(digest-algorithm [ ";" "q" "=" qvalue])` — each algorithm may carry a weight, in RFC 2616's notation, which lets whitespace stand around the `;` and the `=`
- [RFC 7231 §Appendix B](https://www.rfc-editor.org/rfc/rfc7231.html#appendix-B): Where `Content-MD5` was removed from HTTP — RFC 9530 does not mention the field at all
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): Tokens — `token = 1*tchar`, and the fifteen punctuation marks besides the digits and letters that `tchar` admits
- [RFC 9651 §4.2.3.3](https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2.3.3): Parsing a Key: a `key` opens with `lcalpha` or `*` and continues with `lcalpha`, DIGIT, `_`, `-`, `.` or `*` — the production every Dictionary member name and every parameter name is written in, and the one an uppercase letter fails
- [RFC 9651 §4.2.2](https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2.2): Parsing a Dictionary: a member is a key and, optionally, an `=` and a value — a bare key carries the Boolean true rather than being a member without one — and the loop fails on a comma with nothing after it
- [RFC 9651 §3.2](https://www.rfc-editor.org/rfc/rfc9651.html#section-3.2): Dictionaries — keys cannot contain uppercase, unknown members are ignored by recipients, members may be spread across field lines, and an empty Dictionary is spelled by leaving the field out
- [RFC 9651 §4.2.3.1](https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2.3.1): Parsing a Bare Item — seven types chosen by the value's first character, and a single step for a value that is none of them
- [RFC 9651 §2.3](https://www.rfc-editor.org/rfc/rfc9651.html#section-2.3): Parameters are the extension point every Item carries, and a field specification is discouraged from making an unrecognized one an error — so a digest member carrying a parameter RFC 9530 never defined is a digest, read without it
- [RFC 4648 §3.3](https://www.rfc-editor.org/rfc/rfc4648.html#section-3.3): Interpretation of non-alphabet characters — a MUST to reject data outside the base alphabet, unless the referring specification says otherwise
- [RFC 3230 §4.2](https://www.rfc-editor.org/rfc/rfc3230.html#section-4.2): Instance digests: `instance-digest = digest-algorithm "=" <encoded digest output>`, the production a legacy `Digest` member is written in — three parts with nothing bracketed, and an encoding the algorithm's own definition supplies
- [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html): Digest Fields, which obsoletes RFC 3230 and the `Digest` and `Want-Digest` fields with it — the sentence that makes a well-formed legacy field a finding rather than a style preference
- [RFC 9110 §12.4.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.4.2): Quality Values — `weight = OWS ";" OWS "q=" qvalue`, the `qvalue` production and its three-digit fraction, the case-insensitive `q` parameter name, and what a weight of zero means

## Configuration

```toml
[rules.digest_header_syntax]
enabled = true
```

## Examples

### ✅ Good

```http
Content-Digest: sha-256=:YWJj:
```

### ✅ Good — a parameter RFC 9530 never defined is read past, comma and all, as RFC 9651 § 2.3 asks

```http
Content-Digest: sha-256=:YWJj:;note="a, b"
```

### ❌ Bad

```http
Content-Digest: sha-256=dGVzdA==   # missing the required ':' byte sequence delimiters
```

```http
Digest: SHA-256=not-base64!  # legacy Digest is obsoleted by RFC 9530 and will be reported
```

### ❌ Bad — RFC 3230's own example: the field is obsolete, and a `;q=` weight after each algorithm is well formed

```http
Want-Digest: MD5;q=0.3, sha;q=1
```

### ❌ Bad — `Content-MD5` was removed from HTTP, whatever its value

```http
Content-MD5: Q2hlY2sgSW50ZWdyaXR5IQ==
```
