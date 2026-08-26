<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Content Location And Uri Consistent

## Description

Validate `Content-Location` header values. The value must derive from `Content-Location = absolute-URI / partial-URI`: written only with characters a URI is composed from (RFC 3986 §2, which excludes whitespace and the nine visible characters that are not URI characters either — less-than, greater-than, double quote, the two braces, pipe, backslash, caret and backtick — along with every octet at or above %x80), sound percent-encoding and a valid scheme where one is present, and — since neither alternative of the grammar is a comma-separated list — a message carries at most one `Content-Location` field line (RFC 9110 §5.3).

**The value is not a `URI-reference`, and the fragment is the whole difference.** `URI` and `relative-ref` each end in an optional `[ "#" fragment ]` group; `absolute-URI` and `partial-URI` are those two rules with the group dropped, which RFC 9110 §4.1 states in as many words. So `Content-Location: /foo#frag` derives from no reading of the grammar and is reported. Unlike `Referer` — the other field carrying this production — no MUST NOT names the component here: the finding rests on the grammar and §2.2's sender requirement alone, and the message cites those. A percent-encoded `%23` is data, not a fragment.

For 2xx responses the rule additionally compares the value against the request target, resolving a `partial-URI` against it first as RFC 9110 §8.7 requires ("after conversion to absolute form"), so a relative reference that names the target resource is not reported.

**A difference is not a protocol error.** RFC 9110 §8.7 attaches no requirement to a differing `Content-Location`: it means "the origin server claims that the URI is an identifier for a different resource", which is exactly what a negotiated variant, a 201 pointing at the created resource, or a POST report is supposed to say. The rule reports the difference as an advisory — `config_example.toml` ships it at `info` — because the claim "can only be trusted if both identifiers share the same resource owner, which cannot be programmatically determined via HTTP", so it is worth a human glance and nothing stronger. Raise the severity only if your deployment intends `Content-Location` to always echo the target.

## Specifications

- [RFC 9110 §8.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.7): Content-Location: the grammar, and what a value equal to or different from the target URI means. Attaches no requirement to a difference, which is why the mismatch report is an advisory
- [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3): Field Order: a sender MUST NOT emit multiple field lines for a field with no comma-separated-list alternative
- [RFC 9110 §5.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.5): Field Values: singleton fields, and the US-ASCII range field values are constrained to
- [RFC 9110 §4.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-4.1): URI References: a `partial-URI` is the rule for elements that carry a relative URI but no fragment, and an element's ABNF production is what says which forms it allows — the sentence behind reporting a fragment in this field
- [RFC 9110 §2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2): The sender MUST NOT behind the fragment finding: unlike Referer's, this field's section names no component, so a fragment is a protocol element matching no ABNF rule and nothing more
- [RFC 3986 §4.3](https://www.rfc-editor.org/rfc/rfc3986.html#section-4.3): Absolute URI: the form without a fragment identifier — the other half of the alternation, saying the same thing about its half
- [RFC 3986 §5.2](https://www.rfc-editor.org/rfc/rfc3986.html#section-5.2): Relative Resolution: the transform, merge and remove_dot_segments routines used to convert a partial-URI to absolute form before comparing it
- [RFC 3986 §6.2.2.1](https://www.rfc-editor.org/rfc/rfc3986.html#section-6.2.2.1): Case Normalization: scheme and host fold case, the remaining components do not, and the hexadecimal of a percent-triplet that stays encoded is folded to upper case
- [RFC 3986 §6.2.2.2](https://www.rfc-editor.org/rfc/rfc3986.html#section-6.2.2.2): Percent-Encoding Normalization: a triplet standing for an unreserved character is decoded on both sides before comparison, so `/a~b` and `/a%7Eb` are one path. Nothing else is decoded — a delimiter would move the component boundaries (§2.4)
- [RFC 3986 §6.2.2.3](https://www.rfc-editor.org/rfc/rfc3986.html#section-6.2.2.3): Path Segment Normalization: dot-segments are removed from both sides before comparison, after the decoding above — §2.3 names the period among the octets a normalizer decodes, so `%2E%2E` is a dot segment. §6.2.3's scheme-based normalization is NOT applied, so a default port written out and one left off read as different authorities

## Configuration

```toml
[rules.content_location_and_uri_consistent]
enabled = true
severity = "info"
```

## Examples

### ✅ Good

```http
GET /foo HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Location: /foo
Content-Type: text/plain

Hello
```

### ✅ Good (absolute)

```http
GET /foo HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Location: http://example.com/foo
Content-Type: text/plain

Hello
```

### ✅ Good (relative reference resolving to the target)

```http
GET /dir/foo.html HTTP/1.1
Host: example.com

HTTP/1.1 200 OK
Content-Location: foo.html
Content-Type: text/html

<p>Hello
```

### ❌ Bad (invalid percent-encoding)

```http
HTTP/1.1 200 OK
Content-Location: /bad%2G
```

### ❌ Bad (holds a character no URI is composed from)

```http
HTTP/1.1 200 OK
Content-Location: /bad path
```

### ❌ Bad (two field lines — Content-Location is a singleton)

```http
HTTP/1.1 200 OK
Content-Location: /foo
Content-Location: /bar
```

### ❌ Bad (a fragment: neither alternative of the grammar generates one)

```http
HTTP/1.1 200 OK
Content-Location: /foo#frag
```

### ❌ Bad (negotiated variant — reported as an advisory, not an error)

```http
GET /foo HTTP/1.1
Host: example.com
Accept-Language: en

HTTP/1.1 200 OK
Content-Location: /foo.en.html
Content-Type: text/html

<p>Hello
```
