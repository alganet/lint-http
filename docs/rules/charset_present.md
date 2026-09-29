<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Charset Present

## Description

This rule checks if `Content-Type` headers for text-based resources (starting with `text/`) include a `charset` parameter. Responses only, and the type is matched case-insensitively, so `TEXT/HTML` is in scope.

The parameter tells a recipient which character encoding the text was written in. Without it the recipient looks to the content itself, and where the content declares nothing either, it decodes by a default or a guess of its own — and text decoded in an encoding it was not written in is garbled. For `text/html` the finding says where else the page may declare it: HTML requires a page with no byte order mark and no `charset` here to carry a `<meta charset>`, and a header reader cannot see which of those a page has.

No specification requires the parameter — RFC 9110 defines what `charset` means and mandates nothing about sending it — so this rule is a deliberate policy rather than a conformance check. Only the parameter's presence is checked; whether its value names a registered charset is a separate rule's concern.

**The JavaScript types are outside the policy**, because their own registration declines it: RFC 9239 §4 makes the parameter optional on `text/javascript` and the other `text/*` names it registers "despite the recommendation in BCP 13 [RFC6838] for text/* types", a module script is decoded as UTF-8 whatever the parameter says, and UTF-8 is assumed without it. The names are the ones RFC 9239 registers — `text/javascript` with its alias names, and `text/ecmascript` with its — so `text/x-javascript`, which browsers run and nothing registers, is still asked.

**A response with no content to render is skipped**: `1xx`, `204`, `205` and `304`. The hazard this rule names is a recipient guessing the encoding of text it is about to render, and none of those messages carries any — the field beside them describes something the recipient is not receiving. A `304` is the case where the advice was not merely idle but contradictory, since §15.4.5 tells the sender not to generate representation metadata on one at all and `status_304_representation_metadata` reports it. **A response to `HEAD` is deliberately not skipped**: §8.2 makes its representation header fields describe the data a `GET` would have enclosed, so a charset absent there is absent from the representation.

The parameter list is read quote-aware, so a `;` inside a quoted value does not start a new parameter and text that merely looks like `charset=` inside another value does not count. If the quoting never closes, the rule declines to judge rather than report a charset missing that the value plainly carries — an unreadable parameter list is `content_type_valid`'s finding, not an absent charset.

## Violations

- [content_type_charset_missing](../violations/content_type_charset_missing.md) — A text media type does not say which character encoding it used

## Specifications

- [RFC 9110 §8.3.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.1): `media-type` and the case-insensitivity of its type/subtype tokens, which decides what counts as `text/*` here
- [RFC 9110 §8.3.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.2): What `charset` is for. Note it mandates nothing: no requirement to send the parameter exists, so reporting its absence is this crate's policy
- [RFC 9239 §4](https://www.rfc-editor.org/rfc/rfc9239.html#section-4): The JavaScript types' own registration: the `charset` parameter is optional on them despite BCP 13's recommendation for `text/*`, a module script is UTF-8 whatever it says, and UTF-8 is assumed without it — which is why those types are outside this rule
- [HTML Semantics §4.2.5.4](https://html.spec.whatwg.org/multipage/semantics.html#charset): Specifying the document's character encoding — the three places an HTML page may declare it, of which this field is the only one a header reader sees
- [MDN Content-Type](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Type): Content-Type

## Configuration

```toml
[rules.charset_present]
enabled = true
```

## Examples

### ✅ Good Response

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
```

### ❌ Bad Response

```http
HTTP/1.1 200 OK
Content-Type: text/html
# Missing charset parameter
```

### ✅ Good JavaScript, whose registration makes the parameter optional

```http
HTTP/1.1 200 OK
Content-Type: text/javascript
```
