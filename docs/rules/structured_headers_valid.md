<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Structured Headers Valid

## Description

Reports a configured header field whose value fails RFC 9651 Structured Fields parsing. The finding is not that a member is malformed but that the **whole field is gone**: §4.2, "If parsing fails, either the entire field value MUST be ignored … or alternatively the complete HTTP message MUST be treated as malformed", and field specifications are explicitly not allowed to loosen it. One uppercase letter in a Dictionary key costs every other member of the field.

**Each field is parsed as the type it is defined as.** §4.2's algorithm takes a `field_type` — Dictionary, List or Item — and nothing on the wire carries it; the HTTP Field Name Registry's Structured Type column publishes it, and this rule carries that column. `Reporting-Endpoints` has a blank cell, and the Reporting API's §3.2 defines it as a Dictionary. So `Reporting-Endpoints: "https://example.com/r"` is reported: it is a perfectly good String Item, and a Dictionary cannot begin with a DQUOTE, so a browser registers no endpoint. A failure names the member the parse stopped on, under the entry for what went wrong there. A name added to `headers` that nothing types is tried as all three instead, and passes if any of them parses it; when all three fail, the message says what each reading complained about, under `structured_field_malformed`. Point this rule at fields that have no rule of their own — one that reads the members will always say more.

**Every field line is joined first**, as §4.2 requires. A List or Dictionary is a structure over the whole field and its members may be split across lines on purpose; a line judged alone can fail in ways the field does not, and a defect spread across two lines is invisible in either.

**All seven bare-item types**, including the Date (`@1659578233`) and Display String (`%"caf%c3%a9"`) that RFC 9651 added over RFC 8941 — §2.4 is explicit that a parser implementing 9651 also parses everything an 8941 one does. A parameter value is any of them.

**A Dictionary key written twice is reported** although the field parses: §4.2.2 keeps the last and ignores the others, so the earlier ones have no effect and the header still reads as though they did.

**Not reported:** an empty List or Dictionary, which §4.2.1 and §4.2.2 parse into an empty structure rather than failing, and which RFC 9651 spells by leaving the field out — whether writing one anyway is worth saying is each field's question. An empty Item is reported, since §4.2.3 finds no bare item in it and the field is discarded.

## Violations

- [structured_field_character_forbidden](../violations/structured_field_character_forbidden.md) — Structured field holds an octet outside US-ASCII
- [structured_field_inner_list_malformed](../violations/structured_field_inner_list_malformed.md) — Structured field Inner List has no closing parenthesis
- [structured_field_key_duplicated](../violations/structured_field_key_duplicated.md) — Structured field gives one Dictionary key more than once
- [structured_field_key_malformed](../violations/structured_field_key_malformed.md) — Structured field key is not a key production
- [structured_field_malformed](../violations/structured_field_malformed.md) — Structured field value derives from no structured type
- [structured_field_member_empty](../violations/structured_field_member_empty.md) — Structured field writes a comma with no member beside it
- [structured_field_value_empty](../violations/structured_field_value_empty.md) — Structured field writes a value slot with nothing in it
- [structured_field_value_malformed](../violations/structured_field_value_malformed.md) — Structured field value is none of the bare item types

## Specifications

- [RFC 9651 §4.2](https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2): Parsing — the algorithm a recipient runs over a joined field value, the `field_type` it is given, the ASCII conversion it does before choosing one, and the two answers it offers when parsing fails
- [RFC 9651 §4.2.2](https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2.2): Parsing a Dictionary: a member is a key and, optionally, an `=` and a value — a bare key carries the Boolean true rather than being a member without one — and the loop fails on a comma with nothing after it
- [RFC 9651 §4.2.1.2](https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2.1.2): Parsing an Inner List — space-separated Items between a `(` and a `)`, and the failure when the closing parenthesis never arrives
- [RFC 9651 §4.2.3.1](https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2.3.1): Parsing a Bare Item — seven types chosen by the value's first character, and a single step for a value that is none of them
- [RFC 9651 §4.2.3.3](https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2.3.3): Parsing a Key: a `key` opens with `lcalpha` or `*` and continues with `lcalpha`, DIGIT, `_`, `-`, `.` or `*` — the production every Dictionary member name and every parameter name is written in, and the one an uppercase letter fails
- [RFC 9651 §3.3](https://www.rfc-editor.org/rfc/rfc9651.html#section-3.3): The bare item types, including the Date and Display String added over RFC 8941
- [RFC 9651 §2.4](https://www.rfc-editor.org/rfc/rfc9651.html#section-2.4): Why a 9651 parser must accept the two new types: it parses everything an 8941 parser does, and more
- [RFC 9651 §5](https://www.rfc-editor.org/rfc/rfc9651.html#section-5): The registry's "Structured Type" column — where the field_type each field is parsed as is published, for the fields that have one
- [Reporting API §3.2](https://www.w3.org/TR/reporting-1/#header): `Reporting-Endpoints` defined as a Dictionary, the one configured field whose registry cell is blank

## Configuration

```toml
[rules.structured_headers_valid]
enabled = true
# Every field the HTTP Field Name Registry lists as a Structured Field and that
# no other rule here owns -- read off the registry rather than recalled, because
# a list that names a criterion is a claim about a set and this one had drifted
# to four of it. A field is on this list when the registry's "Structured Type"
# column gives it one, or -- where that column is blank -- when the document the
# registry points at declares the type itself: `Reporting-Endpoints` is
# registered with an empty column and its own specification writes
# `Reporting-Endpoints = sf-dictionary`. Registry membership is what bounds the
# list; a field nobody registered is not on it however its draft describes the
# value, which is why `Critical-CH` and the `Sec-CH-UA-*` client hints are absent.
#
# Each field is parsed as the type that column (or its document) gives it; a
# name added here that nothing types is accepted if it parses as any of the
# three. Where a field has its own rule -- Priority, Permissions-Policy, the four
# `Sec-Fetch-*` and `Sec-Fetch-Storage-Access` -- that rule reads its members
# too, and listing it here only doubles the finding.
headers = ["Accept-CH", "Accept-Query", "Activate-Storage-Access",
    "Available-Dictionary", "Cache-Group-Invalidation", "Cache-Groups",
    "Cache-Status", "Capsule-Protocol", "CDN-Cache-Control", "Client-Cert",
    "Client-Cert-Chain", "Concealed-Auth-Export", "Connect-UDP-Bind",
    "Cross-Origin-Embedder-Policy-Report-Only",
    "Cross-Origin-Opener-Policy-Report-Only", "Dictionary-ID",
    "Incremental", "Proxy-Public-Address", "Proxy-Status",
    "Reporting-Endpoints", "Signature", "Signature-Input",
    "Unencoded-Digest", "Use-As-Dictionary", "Want-Unencoded-Digest"]
```

## Examples

### ✅ Good a List, a Dictionary and their parameters

```http
HTTP/1.1 200 OK
Cache-Status: ExampleCache; hit; ttl=376
CDN-Cache-Control: max-age=60, stale-while-revalidate=30
```

### ✅ Good the two types RFC 9651 added to RFC 8941

```http
HTTP/1.1 200 OK
Proxy-Status: revdns; received-at=@1659578233
Cache-Status: ExampleCache; fwd=stale; detail=%"caf%c3%a9"
```

### ❌ Bad an uppercase Dictionary key discards every directive beside it

```http
HTTP/1.1 200 OK
CDN-Cache-Control: Max-Age=60, stale-while-revalidate=30
```

### ❌ Bad a String is written with DQUOTE; nothing here starts an sf-item with an apostrophe

```http
HTTP/1.1 200 OK
Reporting-Endpoints: csp-endpoint='/csp-reports'
```

### ❌ Bad a trailing comma leaves a member with nothing in it

```http
HTTP/1.1 200 OK
Accept-CH: Sec-CH-UA-Platform, Sec-CH-UA-Model,
```

### ❌ Bad a quoted-string with no closing DQUOTE

```http
HTTP/1.1 200 OK
Cache-Status: ExampleCache; key="unterminated
```

### ❌ Bad a Byte Sequence needs the second colon

```http
HTTP/1.1 200 OK
Proxy-Status: revdns; digest=:YWJj
```

### ❌ Bad a String is an Item, and Reporting-Endpoints is a Dictionary

```http
HTTP/1.1 200 OK
Reporting-Endpoints: "https://example.com/reports"
```

### ❌ Bad an Item that opens on its parameters has no bare item

```http
HTTP/1.1 200 OK
Incremental: ;a
```

### ❌ Bad a Dictionary keeps the last of a repeated key

```http
HTTP/1.1 200 OK
CDN-Cache-Control: max-age=60, max-age=5
```

### ❌ Bad an Inner List needs its closing parenthesis

```http
HTTP/1.1 200 OK
Accept-CH: (Sec-CH-UA-Model Sec-CH-UA-Platform
```
