<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Request Accept-Charset Validity

## Description

Check that an `Accept-Charset` header reads as `#( ( token / "*" ) [ weight ] )`: each member a charset name or the literal `*`, optionally followed by a weight whose value is a `qvalue` — `0` to `1` with at most three digits after the point. A request carrying the field at all is also reported, because §12.5.2 deprecates it.

**This is RFC 9110 §12.5's fourth content-negotiation field, and it was the one nothing read.** `Accept`, `Accept-Encoding` and `Accept-Language` each had a rule; every defect below drew nothing on this field while the identical shape drew a finding on a sibling. Two instruments could not have said so: a coverage measure counts entries, and a field with no reader has no entry to be uncovered, while a census of field names asks only of names that appeared on some wire.

**There is no parameter list in this field.** A charset may carry a weight and nothing else, so `utf-8;charset=utf-8` is reported however well formed the pair looks in isolation — the same reading `Accept-Language` and `Accept-Encoding` are given, because all three productions put `[ weight ]` after the primary and stop.

**Three consequences of that reading.** `weight` brackets nothing, so `utf-8;` is a separator introducing a weight that is not there. `[ weight ]` is singular, so `utf-8;q=0.5;q=0.8` is two of something there may be at most one of. And a weight is a MAY — `utf-8, iso-8859-1` is as conforming as `utf-8;q=1, iso-8859-1;q=0.8`.

**The `*` is exempt from the name check and nothing else is.** §12.5.2 gives the asterisk a meaning of its own — it matches every charset not mentioned elsewhere in the field — so it is one of the production's two alternatives rather than a charset called `*`. Every other member is a `token`, and a member that begins at the `;` derives from neither alternative for the arithmetic reason `token_empty` names: both have a one-character floor.

**Whether the name is one anybody registered is a different rule's question.** §12.5.2 sends a reader to §8.3.2 for charset names, and `charset_registered` is the rule that holds that question and the configured list standing in for the IANA registry. It reads this field as its second site, so `Accept-Charset: utf8` is its finding rather than one of these. An operator whose clients send long preference lists will want to widen that rule's `allowed` array: the shipped one is three names, chosen when the only site was a `Content-Type` declaring *the* charset of one representation.

**An empty list element is reported and an empty field value is not.** §5.6.1.1 forbids a sender to generate the element and §5.6.1.2 tells a recipient to ignore it, so `utf-8,,iso-8859-1` is a comma the sender may not write — one finding for the line however many gaps it holds, since what is forbidden is generating the element and a line written with three of them is one list with gaps in it. An empty *value* is a different thing: `#` generates the zero-element list, and §12.5.2 neither gives that a meaning nor forbids it, so the line is passed over.

**The deprecation is reported on the request, once per message.** §12.5.2 names a field a *user agent* sends and its Note deprecates the whole field, naming the costs — wasted bandwidth, added latency, and passive fingerprinting. The IANA HTTP Field Name Registry records the status with no direction attached and this section as the field's only reference, so a request carrying one is the deprecated thing being done. Repeated field lines are one value (§5.2), so two lines are one finding.

**A response's Accept-Charset is read for syntax, and nothing is claimed about the direction.** §12.5.2 gives the field no meaning in a response and forbids one nowhere, exactly as §12.5.4 does for `Accept-Language`; the value is still checked, because a malformed one is malformed wherever it appears. The deprecation finding is not raised there, since the sentence retiring the field is about the field a user agent sends.

**The value is read as the octets the sender wrote**, one `char` per octet. Nothing in this grammar is a quoted-string — a member is a `token`, one literal, and the weight's fixed text — so no octet outside visible US-ASCII is legal anywhere in the field, and every one of them lands inside a production that already has an id for it. Refusing to decode the line would name the octet and take every other defect written beside it out of reach.

## Violations

- [accept_charset_obsolete](../violations/accept_charset_obsolete.md) — A request carries a field this specification deprecates
- [list_member_empty](../violations/list_member_empty.md) — List holds an empty element
- [qvalue_malformed](../violations/qvalue_malformed.md) — Weight is not a qvalue
- [token_character_forbidden](../violations/token_character_forbidden.md) — Token holds a character outside tchar
- [token_empty](../violations/token_empty.md) — Token is written with no characters in it
- [token_whitespace_or_control_forbidden](../violations/token_whitespace_or_control_forbidden.md) — Token holds whitespace or a control character
- [weight_duplicated](../violations/weight_duplicated.md) — Member carries more than one weight
- [weight_equals_whitespace_forbidden](../violations/weight_equals_whitespace_forbidden.md) — Whitespace is written beside the weight's '='
- [weight_malformed](../violations/weight_malformed.md) — Something other than a weight follows the member's ';'
- [weight_missing](../violations/weight_missing.md) — Member writes the weight's ';' and no weight after it

## Specifications

- [RFC 9110 §12.5.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.2): Accept-Charset: `#( ( token / "*" ) [ weight ] )` — the production that says a charset name may carry a weight and nothing else, the meaning given to the `*`, the pointer to §8.3.2 for the names themselves, and the Note that deprecates the field. Like §12.5.4 and unlike §12.5.1 and §12.5.3, it gives the field no meaning in a response
- [RFC 9110 §12.4.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.4.2): Quality Values — `weight = OWS ";" OWS "q=" qvalue`, the `qvalue` production and its three-digit fraction, the case-insensitive `q` parameter name, and what a weight of zero means
- [RFC 9110 §5.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.2): Tokens — `token = 1*tchar`, and the fifteen punctuation marks besides the digits and letters that `tchar` admits
- [RFC 9110 §5.6.1.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.1): The list construct — `1#element => element *( OWS "," OWS element )`, and the sender's MUST NOT against an empty element
- [RFC 9110 §5.6.1.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.2): Recipient Requirements for lists: the bracketing that makes an empty list element something a recipient may ignore. The sender's MUST NOT against generating one is §5.6.1.1's, and this rule reports that one
- [RFC 9110 §8.3.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.2): Charset: where §12.5.2 sends a reader for the names themselves, and the sentence that matches them case-insensitively. Whether a name is one anybody registered is `charset_registered`'s question, not this rule's

## Configuration

```toml
[rules.accept_charset_valid]
enabled = true
```

## Examples

### ❌ Bad (§12.5.2's own example: well formed, and the field is deprecated)

```http
GET / HTTP/1.1
Host: example.com
Accept-Charset: iso-8859-5, unicode-1-1;q=0.8
```

### ❌ Bad (the wildcard, and a weight is optional)

```http
GET / HTTP/1.1
Host: example.com
Accept-Charset: utf-8, *;q=0.1
```

### ❌ Bad (a charset may carry a weight and nothing else)

```http
GET / HTTP/1.1
Host: example.com
Accept-Charset: utf-8;charset=utf-8
```

### ❌ Bad (no qvalue after the separator)

```http
GET / HTTP/1.1
Host: example.com
Accept-Charset: utf-8;
```

### ❌ Bad (a weight there may be at most one of)

```http
GET / HTTP/1.1
Host: example.com
Accept-Charset: utf-8;q=0.5;q=0.8
```

### ❌ Bad (a qvalue is 0 or 1, with at most three digits after the point)

```http
GET / HTTP/1.1
Host: example.com
Accept-Charset: utf-8;q=1.5
```

### ❌ Bad (the weight writes "q=" as one literal, which admits no whitespace)

```http
GET / HTTP/1.1
Host: example.com
Accept-Charset: utf-8;q = 0.5
```

### ❌ Bad (a comma with nothing beside it)

```http
GET / HTTP/1.1
Host: example.com
Accept-Charset: utf-8,,iso-8859-1
```

### ❌ Bad (all weight and no charset)

```http
GET / HTTP/1.1
Host: example.com
Accept-Charset: ;q=0.5
```

### ❌ Bad (a charset name is a token)

```http
GET / HTTP/1.1
Host: example.com
Accept-Charset: utf@8
```
