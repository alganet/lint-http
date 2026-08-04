<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Accept-Encoding Parameter Validity

## Description

Check that an `Accept-Encoding` header reads as `#( codings [ weight ] )`: each member a content coding, the literal `identity`, or the literal `*`, optionally followed by a weight.

**The rule's name is a little wrong, and the reason is the point.** `Accept-Encoding` has no parameter list. A coding may carry a `weight` — `OWS ";" OWS "q=" qvalue` — and nothing else, so there is no `name=value` grammar here to be well formed. What this rule checks is that nothing other than a weight appears: `gzip;charset=utf-8` and `gzip;foo="a;b"` are reported, however well formed the pair looks in isolation, because no derivation of this field produces them.

**Three consequences of the same reading.** `weight` brackets nothing, so `gzip;` is a separator introducing a weight that is not there. `[ weight ]` is singular, so `gzip;q=0.5;q=0.8` is two of something there may be at most one of. And `codings` is not optional, so `;q=0.5` is a member with no coding.

**A weight is a MAY**, so its absence is never reported; `gzip, br` is as conforming as `gzip;q=1.0, br;q=0.5`. When present it must be a `qvalue`: `0` to `1` with at most three digits after the point.

**Both directions are read.** A request states what codings a response may use; a response, per §12.5.3, says what the resource was willing to accept — most often in a 415 (Unsupported Media Type), and evaluated the same way.

**An empty field value is not reported.** §12.5.3 gives it a meaning of its own: the user agent wants no content coding at all.

**Known leniency:** whitespace around the `=` is trimmed, so `q =0.5` is accepted. The production spells the weight as the literal text `"q="` rather than as a parameter with a name and a separator, so there is no room in it for that space at all — but tolerating it never causes a false report, only a missed one.

**An octet outside visible US-ASCII is reported** rather than skipped, unlike the neighbouring `Accept` rules. Those decode such a value because `obs-text` is legal inside a quoted-string; there are no quoted-strings here, so no octet `to_str` refuses can be a legal part of this field.

## Specifications

- [RFC 9110 §12.5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.3): Accept-Encoding: `#( codings [ weight ] )` — the production that says a coding may carry a weight and nothing else. Also the three `codings` alternatives, the meaning of an empty field value, and the meaning of the field in a response
- [RFC 9110 §12.4.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.4.2): Quality Values: the `weight` production this field admits, the `qvalue` its value must be, and the case-insensitive parameter name
- [RFC 9110 §8.4.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.4.1): Content Codings: `content-coding = token`, which is what the character check on each coding enforces
- [RFC 9110 §5.6.1.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.2): Sender Requirements for lists: the bracketing that makes an empty list element something a recipient may ignore

## Configuration

```toml
[rules.message_accept_encoding_parameter_validity]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
GET / HTTP/1.1
Host: example.com
Accept-Encoding: gzip;q=0.8
```

```http
GET / HTTP/1.1
Host: example.com
Accept-Encoding: br;q=1.0
```

```http
GET / HTTP/1.1
Host: example.com
Accept-Encoding: gzip
```

### ✅ Good (wildcard with q)

```http
GET / HTTP/1.1
Host: example.com
Accept-Encoding: *;q=0.5, gzip;q=0.8
```

### ❌ Bad (invalid q precision)

```http
GET / HTTP/1.1
Host: example.com
Accept-Encoding: gzip;q=1.0000
```

### ❌ Bad (invalid coding token)

```http
GET / HTTP/1.1
Host: example.com
Accept-Encoding: gzip@;q=0.5
```

### ❌ Bad (missing q value)

```http
GET / HTTP/1.1
Host: example.com
Accept-Encoding: gzip;q=
```

### ✅ Good (an empty value asks for no coding at all)

```http
GET / HTTP/1.1
Host: example.com
Accept-Encoding:
```

### ❌ Bad (a coding may carry a weight and nothing else)

```http
GET / HTTP/1.1
Host: example.com
Accept-Encoding: gzip;charset=utf-8
```

### ❌ Bad (a weight there may be at most one of)

```http
GET / HTTP/1.1
Host: example.com
Accept-Encoding: gzip;q=0.5;q=0.8
```

### ❌ Bad (a separator introducing a weight that is not there)

```http
GET / HTTP/1.1
Host: example.com
Accept-Encoding: gzip;
```
