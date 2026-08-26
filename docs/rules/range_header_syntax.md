<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Range Header Syntax

## Description

Checks that a `Range` request header field is a well-formed `ranges-specifier`: a range-unit token, an `=`, and a non-empty comma-separated list of range specifiers.

**The unit decides how much can be checked.** RFC 9110 §14.1.1 says the specifier grammar is generic on purpose — "each range unit is expected to specify requirements on when int-range, suffix-range, and other-range are allowed" — and range unit names are an open IANA registry. So for a unit other than `bytes` this rule checks only what holds whatever the unit: that the list has at least one element, that no element is empty (§5.6.1.1 makes an empty list element a sender's MUST NOT), and that each element is one run of visible non-comma characters, which every alternative of `range-spec` is. `Range: items=0-1` is not reported. What an `items` specifier may hold is defined by whoever defined `items`, and an origin server that does not understand a unit is told by §14.2 to ignore the field, not to treat it as malformed.

**For `bytes` it also checks the two forms that unit defines**: `first-pos "-" [ last-pos ]` and `"-" suffix-length`, every position `1*DIGIT`, the last position not below the first, and no third form — §14.1.2 says "Byte ranges do not use the other-range specifier". Positions are compared as decimal numerals rather than parsed into an integer, because the same section requires recipients to "anticipate potentially large decimal numerals" without failing on overflow.

**All of the field's lines are joined before parsing**, in order and separated by comma SP, because that is the value a recipient acts on: `bytes=0-1` on one line and `bytes=2-3` on the next make one range-set whose second element no byte range specifier admits.

**What it does not report.** Whether a range is *satisfiable* — that depends on the length of the selected representation, which no request carries. A `Range` on a method other than GET — the requirement there is on the server, which must ignore such a field; nothing addresses the client that sent it. Overlapping or descending ranges — §14.2 asks for ascending order with a SHOULD that ends "unless there is a specific need to request a later part earlier", and a request records the ranges rather than the need.

**What a finding costs.** §14.2 lets a server that supports range requests "ignore or reject" a field carrying an invalid ranges-specifier, so the price of one is the range request rather than the request — a client that asked for part of a representation is answered with all of it.

## Specifications

- [RFC 9110 §14.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.1.1): Range Specifiers: `ranges-specifier = range-unit "=" range-set`, and the grammar under it is generic — each range unit says which of `int-range`, `suffix-range` and `other-range` its specifiers may use. A ranges-specifier is invalid when it holds a range-spec "that is invalid or undefined for the indicated range-unit", which is the sentence every check here rests on and the one that bounds them to the unit the rule knows
- [RFC 9110 §14.1.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.1.2): Byte Ranges: the two forms the `bytes` unit defines, both `1*DIGIT`, with `other-range` withdrawn for this unit. It also requires recipients to anticipate potentially large decimal numerals and prevent parsing errors due to integer conversion overflows — so positions are compared as digits and no ceiling is imposed — and it defines satisfiability, which is a question about the representation and not about the field
- [RFC 9110 §14.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.2): `Range`: the field is a `ranges-specifier` on a GET request. A server MUST ignore one received with a method for which range handling is not defined, an origin server MUST ignore one whose range unit it does not understand, and a server that supports range requests MAY ignore or reject an invalid one — which is what a finding here costs. The ascending-order requirement is a SHOULD carrying an exception about the client's own needs, which a request does not record
- [RFC 9110 §14.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.1): Range Units: `range-unit = token`, case-insensitive, an open registry, "intended to be extensible" — which is why a unit other than `bytes` is not a finding
- [RFC 9110 §5.6.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1): Sender Requirements for the list construct: OWS on either side of each comma, and a sender MUST NOT generate empty list elements. Recipients are told the opposite in §5.6.1.2 — parse and ignore them — so the shared list reader, which drops them, cannot answer this rule's question

## Configuration

```toml
[rules.range_header_syntax]
enabled = true
severity = "error"
```

## Examples

### ✅ Good

```http
GET /big-file HTTP/1.1
Host: example.com
Range: bytes=0-499

GET /big-file HTTP/1.1
Host: example.com
Range: bytes=500-999,1000-1499

GET /big-file HTTP/1.1
Host: example.com
Range: bytes=-500

GET /big-file HTTP/1.1
Host: example.com
Range: bytes=9500-
```

### ✅ Good (a range unit this rule does not model)

```http
GET /catalogue HTTP/1.1
Host: example.com
Range: items=0-1
```

### ❌ Bad

```http
GET /big-file HTTP/1.1
Host: example.com
Range: bytes=abc

GET /big-file HTTP/1.1
Host: example.com
Range: bytes=5-3
```
