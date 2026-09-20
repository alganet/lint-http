<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# The representation metadata a 304 does not owe

## Description

A `304 (Not Modified)` exists to transfer as little as possible: the recipient already holds the representation, and RFC 9110 §15.4.5 lists the header fields the response owes — `Content-Location`, `Date`, `ETag`, `Vary`, `Cache-Control` and `Expires` — and then tells a sender not to generate *representation metadata* beyond them.

**The prohibition is written against a class, and names no member of it.** §8.2 is where the class is defined and §8.3 to §8.7 enumerate it one field per subsection: `Content-Type`, `Content-Encoding`, `Content-Language`, `Content-Length` and `Content-Location`. This rule reads the first three.

**The two it does not read are exempt by a sentence each, not by judgement.** `Content-Location` is on §15.4.5's own MUST list. `Content-Length` has an explicit MAY of its own in §8.6, where on a 304 it means the length of the `200` that was not sent; `no_body_for_1xx_204_304` documents the same carve-out from the other side.

**One finding per field.** A response carrying `Content-Type` *and* `Content-Language` is two things to take off it, and each finding names the field and the value as written, so an operator can find the line.

**The escape clause is read narrowly, and this is the rule's one judgement.** §15.4.5 permits metadata that "exists for the purpose of guiding cache updates", and its own example of that is a *validator* — `Last-Modified` where there is no `ETag`. A cache does update its stored header fields from a 304 (RFC 9111 §4.3.4), so a wide reading of the clause would permit every field and leave the SHOULD NOT with nothing to forbid. The narrow reading is taken: a field that describes the representation is the information transfer the status code was chosen to avoid, not a thing that guides the update.

**Read against the response alone.** Every other check about a 304 in this crate compares it with the request it answers or with an earlier message; this one is decided by the status code and a field beside it, which is why it is its own rule and not an arm of the conditional-request one.

## Violations

- [status_304_metadata_forbidden](../violations/status_304_metadata_forbidden.md) — A 304 sends representation metadata beyond the fields it owes

## Specifications

- [RFC 9110 §15.4.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.5): 304 Not Modified — the fields a 304 MUST send, the SHOULD NOT against any other representation metadata unless it guides cache updates, and the response being terminated by the end of the header section
- [RFC 9110 §8.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.2): Representation Metadata — the representation header fields, whose members § 8.3 to § 8.7 define one per subsection: Content-Type, Content-Encoding, Content-Language, Content-Length and Content-Location. § 15.4.5's SHOULD NOT is written against this class and names no member of it
- [RFC 9110 §8.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.6): Content-Length — a MUST NOT on 1xx and 204 at any value, and a MAY on a 304 to a conditional GET. That MAY's own MUST NOT (the value must equal the unsent 200's content length) is undecidable from one exchange and is left unenforced
- [RFC 9110 §8.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.7): Content-Location — representation metadata by its own words, and the one member of the class a 304 is told to send rather than to withhold, which is why it is exempt here by name

## Configuration

```toml
[rules.status_304_representation_metadata]
enabled = true
```

## Examples

### ✅ Good 304 — the fields §15.4.5 has it generate, and nothing else

```http
HTTP/1.1 304 Not Modified
Date: Mon, 01 Jan 2024 00:00:00 GMT
ETag: "abc"
Vary: Accept-Encoding
Cache-Control: max-age=60
Content-Location: /a
```

### ✅ Good 304 — Content-Length has a MAY of its own in §8.6

```http
HTTP/1.1 304 Not Modified
ETag: "abc"
Content-Length: 1024
```

### ❌ Bad 304 — the media type of a representation the client already has

```http
HTTP/1.1 304 Not Modified
ETag: "abc"
Content-Type: text/html
```

### ❌ Bad 304 — the language of that same representation

```http
HTTP/1.1 304 Not Modified
ETag: "abc"
Content-Language: en
```

### ❌ Bad 304 — a coding describing content that was not sent

```http
HTTP/1.1 304 Not Modified
ETag: "abc"
Content-Encoding: gzip
```
