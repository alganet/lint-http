<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Priority Header Syntax

## Description

Reports a `Priority` header field (RFC 9218) carrying a priority parameter that will not take effect. Nothing here is "invalid": §4 defines **ignore** semantics, so the finding is always that the sender wrote a signal a recipient will discard, at one of two scopes.

**The whole field, or one parameter.** `Priority` is a Structured Fields Dictionary and §4 says receivers parse it as one, so a parse failure discards everything — RFC 9651 §4.2, "If parsing fails, either the entire field value MUST be ignored … or alternatively the complete HTTP message MUST be treated as malformed". One uppercase letter in a key, or `i=?2` where `?2` is not a Boolean, costs every parameter in the field. A parameter that parses but says something unusable costs only itself: §4, "unknown priority parameters, priority parameters with out-of-range values, or values of unexpected types MUST be ignored". The messages say which.

**What each of the two defined parameters must be.** `u` is an Integer between 0 and 7 inclusive (§4.1); `i` is a Boolean (§4.2), and a bare `i` is that Boolean's `true`, which is why `u=5, i` is the RFC's own example. A bare `u` is *also* Boolean true, and therefore a value of unexpected type — the one place where leaving a value out is a defect rather than a shorthand. Leading zeros are not: RFC 9651 §3.3.1 permits `u=03`.

**Being ignored costs different things in the two directions.** §8: in a request, omitting a parameter means its default, so an ignored `u` becomes 3 and an ignored `i` becomes false. In a response, absence means the server does not wish to change the client's value, so an ignored parameter loses the server's view entirely with nothing substituted.

**Every field line is joined first**, as RFC 9651 §4.2 requires — this rule used to read only the first `Priority` header of a message.

**A repeated key is reported.** RFC 9651 §4.2.2 keeps only the last instance and says nothing about it, so `u=1, u=5` looks like two urgencies and is one; the earlier parameter is dead text no recipient will see.

**Not reported:** an unknown parameter key. The "HTTP Priority" registry (§4.3.1) is open by design and holds only `u` and `i` today, so a key this rule does not know is an extension doing what §4.3 contemplates, and §4's MUST to ignore it is what makes sending one safe. Nor an empty field value, which RFC 9651 §4.2.2 parses into an empty Dictionary: it expresses no preference rather than failing.

## Specifications

- [RFC 9218 §4](https://www.rfc-editor.org/rfc/rfc9218.html#section-4): Priority Parameters — the Dictionary encoding, and the MUST to ignore an unknown parameter, an out-of-range value or a value of unexpected type rather than treat it as an error
- [RFC 9218 §4.1](https://www.rfc-editor.org/rfc/rfc9218.html#section-4.1): Urgency — an Integer between 0 and 7 inclusive, defaulting to 3
- [RFC 9218 §4.2](https://www.rfc-editor.org/rfc/rfc9218.html#section-4.2): Incremental — a Boolean, defaulting to false
- [RFC 9218 §8](https://www.rfc-editor.org/rfc/rfc9218.html#section-8): Why an ignored parameter costs different things in a request and in a response: only in a request does omission imply the default
- [RFC 9218 §4.3.1](https://www.rfc-editor.org/rfc/rfc9218.html#section-4.3.1): The "HTTP Priority" registry — open, and holding only u and i, which is why an unrecognised key is not a finding
- [RFC 9651 §4.2](https://www.rfc-editor.org/rfc/rfc9651.html#section-4.2): Structured Fields parsing — the MUST to join field lines, and the discard rule that makes one malformed parameter cost the whole field

## Configuration

```toml
[rules.priority_header_syntax]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good (a bare i is the Boolean true — RFC 9218's own example)

```http
GET /image.jpg HTTP/1.1
Priority: u=5, i
```

### ✅ Good

```http
HTTP/1.1 200 OK
Priority: u=1
```

### ✅ Good (an unregistered key is an extension, and MUST be ignored rather than rejected)

```http
GET /style.css HTTP/1.1
Priority: u=0, visible=?1
```

### ❌ Bad (an urgency outside 0-7 is ignored, so the request gets the default 3)

```http
GET /script.js HTTP/1.1
Priority: u=8
```

### ❌ Bad (a bare u is Boolean true, not an Integer)

```http
GET /script.js HTTP/1.1
Priority: u
```

### ❌ Bad (?2 is not a Boolean, and the parse failure discards the urgency beside it)

```http
GET /image.jpg HTTP/1.1
Priority: u=5, i=?2
```

### ❌ Bad (u given twice is one urgency, not two: all but the last are ignored)

```http
GET /image.jpg HTTP/1.1
Priority: u=1, u=5
```
