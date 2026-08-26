<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Accept-Language Weight Validity

## Description

Check that an `Accept-Language` header reads as `#( language-range [ weight ] )`: each member a language range, optionally followed by a weight whose value is a `qvalue` — `0` to `1` with at most three digits after the point.

**There is no parameter list in this field.** A range may carry a weight and nothing else, so `en;charset=utf-8` is reported however well formed the pair looks in isolation. The rule used to check that parameter names were tokens and values were tokens or quoted-strings, which is the parameter grammar of a *different* kind of field; its own SpecRef note said it was following "the same q/parameter validation semantics used across other headers in this project".

**Three consequences of the same reading.** `weight` brackets nothing, so `en;` and `en;;q=0.5` are separators introducing a weight that is not there. `[ weight ]` is singular, so `en;q=0.5;q=0.8` is two of it. And a weight is optional — `en, fr` is as conforming as `en;q=1, fr;q=0.8`.

**The language range itself is not checked here.** That is `language_tag_syntax`'s subject: it reports an empty range, whitespace inside one, and an over-long subtag, and lets `*` through.

**A response's Accept-Language is read, but the spec does not describe one.** This is the asymmetry worth knowing about: §12.5.1 and §12.5.3 each say what `Accept` and `Accept-Encoding` mean when a server sends them in a response, and §12.5.4 says no such thing — it defines a request field and stops. The value is still checked, because a malformed one is malformed wherever it appears, but the finding is about syntax and claims nothing about meaning.

**Known leniency:** whitespace around the `=` is trimmed, so `q =0.5` is accepted, though `weight` spells the text as the literal `"q="`. It can only miss a report, never invent one.

**An octet outside visible US-ASCII is reported** rather than skipped: nothing in this grammar is a quoted-string, so no such octet can be a legal part of the field.

## Specifications

- [RFC 9110 §12.5.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.4): Accept-Language: `#( language-range [ weight ] )` — the production that says a range may carry a weight and nothing else. Note that, unlike Accept and Accept-Encoding, this section gives the field no meaning in a response
- [RFC 9110 §12.4.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.4.2): Quality Values: the `weight` production this field admits, the `qvalue` its value must be, and the case-insensitive parameter name
- [RFC 4647 §2.1](https://www.rfc-editor.org/rfc/rfc4647.html#section-2.1): Basic Language Range: where `language-range` is defined, by reference from RFC 9110. Its syntax is `language_tag_syntax`'s subject, not this rule's
- [RFC 9110 §5.6.1.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.2): Sender Requirements for lists: the bracketing that makes an empty list element something a recipient may ignore

## Configuration

```toml
[rules.accept_language_weight_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
GET / HTTP/1.1
Host: example.com
Accept-Language: en-US, fr;q=0.8
```

### ✅ Good (the wildcard range, and a weight is optional)

```http
GET / HTTP/1.1
Host: example.com
Accept-Language: *;q=0.5, en;q=0.7
```

### ✅ Good (RFC 9110 §12.5.4's own example)

```http
GET / HTTP/1.1
Host: example.com
Accept-Language: da, en-gb;q=0.8, en;q=0.7
```

### ❌ Bad (a qvalue has at most three digits after the point)

```http
GET / HTTP/1.1
Host: example.com
Accept-Language: en;q=1.0000
```

### ❌ Bad (a range may carry a weight and nothing else)

```http
GET / HTTP/1.1
Host: example.com
Accept-Language: en;badparam=value
```

### ❌ Bad (a well-formed parameter the field still has no room for)

```http
GET / HTTP/1.1
Host: example.com
Accept-Language: en;foo="a\"b"
```

### ❌ Bad (no qvalue after the separator)

```http
GET / HTTP/1.1
Host: example.com
Accept-Language: en;q=
```

### ❌ Bad (a weight there may be at most one of)

```http
GET / HTTP/1.1
Host: example.com
Accept-Language: en;q=0.5;q=0.8
```
