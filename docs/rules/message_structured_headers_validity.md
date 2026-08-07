<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Structured Headers Validity

## Description

Reports a configured header field whose value fails RFC 9651 Structured Fields parsing. The finding is not that a member is malformed but that the **whole field is gone**: §4.2, "If parsing fails, either the entire field value MUST be ignored … or alternatively the complete HTTP message MUST be treated as malformed", and field specifications are explicitly not allowed to loosen it. One uppercase letter in a Dictionary key costs every other member of the field.

**All three types are tried, because there is no way to know which one applies.** §4.2's algorithm takes a `field_type` — Dictionary, List or Item — and nothing on the wire carries it; the `headers` option names bare field names. So a value passes if any of the three parses it, which means `Priority: "u"` is accepted here: it is a perfectly good String Item, just not the Dictionary that field was defined as. When all three fail, the message says what each reading complained about, since telling a Dictionary it is an invalid Item tells it nothing. Point this rule at fields that have no rule of their own — one that knows the type will always say more.

**Every field line is joined first**, as §4.2 requires. A List or Dictionary is a structure over the whole field and its members may be split across lines on purpose; a line judged alone can fail in ways the field does not, and a defect spread across two lines is invisible in either.

**All seven bare-item types**, including the Date (`@1659578233`) and Display String (`%"caf%c3%a9"`) that RFC 9651 added over RFC 8941 — §2.4 is explicit that a parser implementing 9651 also parses everything an 8941 one does. A parameter value is any of them.

**Not reported:** an empty field value, which §4.2.1 and §4.2.2 both parse into an empty structure rather than failing; and a duplicate Dictionary key, which §4.2.2 resolves silently in favour of the last one — a defect worth reporting, but only by a rule that knows the field is a Dictionary.

## Specifications

- [RFC 9651 §4.2](https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2): Parsing — the algorithm this rule runs, the field_type it needs and does not have, the MUST to join field lines, and the discard rule that makes a failure cost the whole field
- [RFC 9651 §3.3](https://www.rfc-editor.org/rfc/rfc9651.html#section-3.3): The bare item types, including the Date and Display String added over RFC 8941
- [RFC 9651 §2.4](https://www.rfc-editor.org/rfc/rfc9651.html#section-2.4): Why a 9651 parser must accept the two new types: it parses everything an 8941 parser does, and more
- [RFC 9651 §5](https://www.rfc-editor.org/rfc/rfc9651.html#section-5): The registry's "Structured Type" column — where the field_type this rule lacks is published, for the fields that have one

## Configuration

```toml
[rules.message_structured_headers_validity]
enabled = true
severity = "warn"
# Fields the HTTP Field Name Registry gives a Structured Type and that no other
# rule here owns. This rule cannot know which type a field was defined as, so it
# accepts a value that parses as any of the three; where a field has its own
# rule -- Priority, Permissions-Policy -- that rule knows the type and reports
# more precisely, and listing it here only doubles the finding.
headers = ["Accept-CH", "Cache-Status", "CDN-Cache-Control", "Proxy-Status"]
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
