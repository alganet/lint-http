<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Digest Header Syntax

## Description

RFC 9530 obsoletes RFC 3230 and defines modern Integrity fields: `Content-Digest` (for message content), `Repr-Digest` (for representation data) and their preference counterparts `Want-Content-Digest` / `Want-Repr-Digest`. This rule validates:

- **Legacy** `Digest` / `Want-Digest` header syntax (alg=base64) and flags their use as obsoleted by RFC 9530.
- **New** RFC 9530 Integrity fields (`Content-Digest`, `Repr-Digest`) must follow the structured dictionary syntax (e.g., `sha-256=:BASE64:`) with byte sequences that decode as valid Base64.
- **Integrity preference** fields (`Want-Content-Digest`, `Want-Repr-Digest`) use algorithm=weight pairs where weight is an integer in 0..=10.
- **Obsolete field**: presence of `Content-MD5` is flagged. It was removed from HTTP by RFC 7231 (not by RFC 9530, which does not mention it); prefer `Content-Digest`.

Algorithm names in the RFC 9530 fields are structured-field Dictionary keys and so must be lowercase (`sha-256`, not the `SHA-256` spelling used by the obsolete `Digest` field, whose algorithm token is case-insensitive).

## Specifications

- [RFC 9530 §2](https://www.rfc-editor.org/rfc/rfc9530.html#section-2): `Content-Digest`: a Dictionary keyed by hashing algorithm whose values are Byte Sequences
- [RFC 9530 §3](https://www.rfc-editor.org/rfc/rfc9530.html#section-3): `Repr-Digest`: the same syntax over representation data rather than message content
- [RFC 9530 §4](https://www.rfc-editor.org/rfc/rfc9530.html#section-4): `Want-Content-Digest` / `Want-Repr-Digest`: a Dictionary whose values are Integers in the range 0 to 10 inclusive
- [RFC 3230 §4.1.1](https://www.rfc-editor.org/rfc/rfc3230.html#section-4.1.1): Historical `Digest` / `Want-Digest`, obsoleted by RFC 9530: `digest-algorithm = token`, case-insensitive — which is why uppercase is valid there and not in the structured fields
- [RFC 7231 §Appendix B](https://www.rfc-editor.org/rfc/rfc7231.html#appendix-B): Where `Content-MD5` was removed from HTTP — RFC 9530 does not mention the field at all
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): Tokens — `token = 1*tchar`, and the fifteen punctuation marks besides the digits and letters that `tchar` admits
- [RFC 9651 §4.2.3.3](https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2.3.3): Parsing a Key: a `key` opens with `lcalpha` or `*` and continues with `lcalpha`, DIGIT, `_`, `-`, `.` or `*` — the production every Dictionary member name and every parameter name is written in, and the one an uppercase letter fails
- [RFC 9651 §4.2.2](https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2.2): Parsing a Dictionary: a member is a key and, optionally, an `=` and a value — a bare key carries the Boolean true rather than being a member without one — and the loop fails on a comma with nothing after it
- [RFC 4648 §3.3](https://www.rfc-editor.org/rfc/rfc4648.html#section-3.3): Interpretation of non-alphabet characters — a MUST to reject data outside the base alphabet, unless the referring specification says otherwise
- [RFC 3230 §4.2](https://www.rfc-editor.org/rfc/rfc3230.html#section-4.2): Instance digests: `instance-digest = digest-algorithm "=" <encoded digest output>`, the production a legacy `Digest` member is written in — three parts with nothing bracketed, and an encoding the algorithm's own definition supplies
- [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html): Digest Fields, which obsoletes RFC 3230 and the `Digest` and `Want-Digest` fields with it — the sentence that makes a well-formed legacy field a finding rather than a style preference

## Configuration

```toml
[rules.digest_header_syntax]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Content-Digest: sha-256=:YWJj:
```

### ❌ Bad

```http
Content-Digest: sha-256=dGVzdA==   # missing the required ':' byte sequence delimiters
```

```http
Digest: SHA-256=not-base64!  # legacy Digest is obsoleted by RFC 9530 and will be reported
```
