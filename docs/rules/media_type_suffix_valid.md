<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Media Type Suffix Validity

## Description

Flags media types — in `Content-Type` on either side of a transaction, or in any member of a request `Accept` — whose subtype ends in a `+suffix` that is not in the list you configure. A suffix names the structured syntax the payload is written in (`+json`, `+xml`), so a misspelled one is a claim about the payload that recipients cannot act on: RFC 6838 §4.2.8 says media types "MUST NOT be given names incorporating suffixes for structured syntaxes they do not actually employ", and that "+suffix constructs for as-yet unregistered structured syntaxes SHOULD NOT be used". A subtype ending in a bare `+` is reported too — it appends nothing and so names no syntax — as is one that is *only* a suffix (`application/+json`), which has no base name for the suffix to qualify.

**It does not consult the IANA registry**, despite what its SpecRef points at: there is no lookup, and a suffix is "registered" as far as this rule is concerned exactly when your `allowed` array covers it. Comparison is case-insensitive, because the subtype a suffix lives in is.

**Scope:** only the suffix, and only on a subtype that is a well-formed name. Whether the media type parses at all, whether the subtype's characters are legal, and whether more than one `Content-Type` field line is present are all `content_type_valid`'s findings; whether the full media type is one you allow is `content_type_registered`'s. A subtype carrying characters no name may contain is skipped here rather than reported as a bad suffix — that would name the wrong defect, and say it twice.

## Specifications

- [RFC 6838 §4.2.8](https://www.rfc-editor.org/rfc/rfc6838.html#section-4.2.8): Structured Syntax Name Suffixes: that an unregistered `+suffix` SHOULD NOT be used, and — the sharper half — that a suffix MUST NOT name a syntax the type does not employ
- [RFC 6838 §4.2](https://www.rfc-editor.org/rfc/rfc6838.html#section-4.2): Naming Requirements: `restricted-name`, which decides where a suffix starts ("characters after last plus") and that a name must begin with ALPHA or DIGIT — so a subtype that is only a suffix has no base name
- [RFC 9110 §8.3.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.1): Media Type: the subtype a suffix lives in is case-insensitive, which is why suffixes are compared folded
- [IANA Media Type Structured Suffixes](https://www.iana.org/assignments/media-type-structured-suffix/media-type-structured-suffix.xhtml): The registry this rule stands in for but does not read; the configured `allowed` array is what it actually checks against

## Configuration

```toml
[rules.media_type_suffix_valid]
enabled = true
severity = "warn"
# Six names from IANA's Structured Syntax Suffix registry. The list used to
# hold "exi" as a seventh -- a name that registry has never held: "exi" is a
# registered HTTP *content coding* (W3C EXI), and it had been copied here from
# the neighbouring registry, silencing exactly the finding this rule exists to
# make for "+exi". As with every allowed list, the registry is not consulted
# at lint time; this array stands in for it, so its contents have to be read
# against the registry they name.
allowed = ["json", "xml", "ber", "der", "fastinfoset", "wbxml"]
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Content-Type: application/ld+json
```

### ✅ Good (+xml)

```http
HTTP/1.1 200 OK
Content-Type: image/svg+xml
```

### ✅ Good (Accept member)

```http
GET / HTTP/1.1
Host: example.com
Accept: application/vnd.example+json; q=0.8
```

### ❌ Bad (unknown suffix)

```http
HTTP/1.1 200 OK
Content-Type: application/vnd.example+unknown
```

### ❌ Bad (unknown suffix in an Accept member)

```http
GET / HTTP/1.1
Host: example.com
Accept: application/bar+nope
```

### ❌ Bad (a bare `+` appends nothing)

```http
HTTP/1.1 200 OK
Content-Type: application/vnd.example+
```
