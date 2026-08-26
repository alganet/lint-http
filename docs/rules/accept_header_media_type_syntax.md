<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Accept Header Media Type Syntax

## Description

Check that an `Accept` header reads as `#( media-range [ weight ] )`: each member a `media-range` — `*/*`, `type/*`, or `type/subtype`, both halves `token` — optionally followed by media type parameters and then a weight. A `q` value must be a `qvalue`: `0` to `1` with at most three digits after the decimal point.

**A bare `*` is reported**, and so is a wildcard type with a concrete subtype (`*/json`). The second of those is a judgement about the prose rather than a reading of the ABNF: `type` is a `token` and `*` is a `tchar`, so `*/json` does derive from `type "/" subtype`. But §12.5.1 gives the asterisk exactly two jobs — all media types, or all subtypes of one type — and this is neither, so it names no set a recipient could match against. `content_type_valid` takes the same position on the same shape in `Content-Type`.

**A parameter after the weight is reported.** `Accept = #( media-range [ weight ] )` puts the weight last and the media-range is what carries the parameters, so `text/html;q=0.5;charset=utf-8` derives from nothing in this grammar. RFC 9110 removed the `accept-ext` production that used to allow it and states the consequence as a SHOULD on senders. Finding the `q` itself is unaffected: it is looked for among all the parameters and its name matched case-insensitively, because §12.5.1 tells recipients to process it regardless of ordering. This rule reports what a sender did; it does not pretend not to understand it.

**Both directions are read.** A request's `Accept` states a preference; a response's, per §12.5.1, says what a subsequent request to the same resource should prefer. Each field line is validated on its own rather than recombined, so an unbalanced quote in one line cannot swallow the members of the next.

**Quoting that never closes is reported here** rather than declined. The rules that consume `Accept` — `accept_and_content_type_negotiation` among them — decline to judge a member list they cannot read; this rule is the one that owns a malformed `Accept`, so declining would leave the defect with no reporter.

**Whitespace inside a media-range is reported.** The OWS these grammars allow sits around list elements and around the `;` before a parameter, never between a type and its subtype, so `text /html` is malformed — and used to pass, because the media-type helper trims each half before returning it and the space vanished before any check saw it.

**Known leniency:** RFC 9110 §5.6.6 forbids whitespace around a parameter's `=`, and this rule trims it, so `q =0.5` is accepted. Empty list elements (`text/html, , text/plain`) are skipped, which §5.6.1.2 permits a recipient to do.

## Specifications

- [RFC 9110 §12.5.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.1): Accept: the `#( media-range [ weight ] )` list, the three shapes a `media-range` takes and what the asterisk ranges over, the removal of the extension parameters that once followed the weight, and the meaning of an Accept sent in a response
- [RFC 9110 §12.4.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.4.2): Quality Values: the `qvalue` production and its three-digit bound, and that the parameter name is matched case-insensitively
- [RFC 9110 §8.3.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.1): Media Type: `type` and `subtype` are both `token`, which is what the character checks enforce
- [RFC 9110 §5.6.6](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.6): Parameters: the `name=value` grammar and the two alternatives a value may take. Its prohibition on whitespace around `=` is NOT enforced here
- [RFC 9110 §5.6.1.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.2): Sender Requirements for lists: the bracketing that makes an empty list element something a recipient may ignore

## Configuration

```toml
[rules.accept_header_media_type_syntax]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Accept: text/html
```

### ✅ Good (a media type parameter, then the weight)

```http
Accept: text/*;q=0.8, application/json;charset=utf-8;q=0.9
```

### ✅ Good (a comma inside a quoted value is not a separator)

```http
Accept: text/html;foo="a,b", */*;q=0.1
```

### ❌ Bad (the asterisk names a type or a subtype, not a pair)

```http
Accept: *
```

### ❌ Bad (a wildcard type ranges over nothing without a wildcard subtype)

```http
Accept: */json
```

### ❌ Bad (no subtype)

```http
Accept: text; q=0.8
```

### ❌ Bad (a qvalue has at most three digits after the point)

```http
Accept: text/html; q=1.0000
```

### ❌ Bad (the weight closes a media-range)

```http
Accept: text/html; q=0.5; charset=utf-8
```

### ❌ Bad (a parameter is a name, an "=", and a value)

```http
Accept: text/html; charset
```

### ❌ Bad (the quoting never closes)

```http
Accept: text/html; foo="unterminated
```
