<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Preference-Applied header validity

## Description

Check the `Preference-Applied` response header against its RFC 7240 §3 grammar — `Preference-Applied = 1#applied-pref`, `applied-pref = token [ BWS "=" BWS word ]` — and against the request that produced it: the field's members are the preferences the server honored, so a member the request's `Prefer` header never asked for, or one reported with a different value than was asked for, is the message contradicting itself.

The field's lines are joined before they are split, because a client may spread `Prefer` over several lines and RFC 7240 §2 says several lines are one value; the value is read as octets, because a `word` may be a `quoted-string` and `qdtext` admits `obs-text`. Comparisons follow §2: preference names are matched case-insensitively, values case-sensitively, and a value's quoting is not part of it — `foo="bar"` and `foo=bar` name the same value, and `foo=""` and `foo` both mean no value at all.

What it does not decide: whether a value is one the preference's own definition allows (RFC 7240 §4 gives `return` and `handling` closed value sets; `message_prefer_header_valid` is the rule holding the request those come from), and whether the `Prefer` the capture holds is the one the responding server saw — an intermediary between this observation point and the origin may add preferences of its own, so the comparison is against this exchange as observed. When the request's `Prefer` value cannot be split into members — its quoting never closes, or a member does not parse — both comparisons stand down rather than report as unrequested what is merely unreadable; the grammar checks on the response are unaffected.

## Specifications

- [RFC 7240 §3](https://www.rfc-editor.org/rfc/rfc7240.html#section-3): `Preference-Applied` — the field's definition, its grammar, and the sentence saying it is the `Prefer` grammar without parameters
- [RFC 7240 §2](https://www.rfc-editor.org/rfc/rfc7240.html#section-2): `Prefer` — the multi-line equivalence, the first-instance rule, the case rules for names and values, and the equivalence of an empty value with no value
- [RFC 7240 §1.1](https://www.rfc-editor.org/rfc/rfc7240.html#section-1.1): Where `token`, `word`, `OWS`, `BWS` and the `#rule` extension come from. The named source is RFC 7230, which RFC 9110 obsoletes; `word` is the one name RFC 9110 did not keep, though both halves of it survive as `token` and `quoted-string`
- [RFC 9110 §5.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1): The `#rule` extension: §5.6.1.1 forbids the sender an empty list element, §5.6.1.2 prints the values a `1#` production rejects for having no non-empty member
- [RFC 9110 §5.6.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.3): `BWS`: a recipient must remove it before interpreting the element, and a sender must not have written it — both directions are read at the `=` in `applied-pref`

## Configuration

```toml
[rules.message_preference_applied_header_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good (RFC 7240 §3's own example exchange)

```http
PATCH /my-document HTTP/1.1
Host: example.org
Content-Type: application/example-patch
Prefer: return=representation

HTTP/1.1 200 OK
Content-Type: application/json
Preference-Applied: return=representation
Content-Location: /my-document
```

### ✅ Good (the value's quoting is not part of the value)

```http
GET / HTTP/1.1
Host: example.org
Prefer: return="representation"

HTTP/1.1 200 OK
Preference-Applied: return=representation
```

### ✅ Good (server names the preference and leaves its value unstated)

```http
GET / HTTP/1.1
Host: example.org
Prefer: return=representation

HTTP/1.1 200 OK
Preference-Applied: return
```

### ❌ Bad (applied preference the request never asked for)

```http
GET / HTTP/1.1
Host: example.org

HTTP/1.1 200 OK
Preference-Applied: respond-async
```

### ❌ Bad (applied-pref has no parameters)

```http
GET / HTTP/1.1
Host: example.org
Prefer: return=representation

HTTP/1.1 200 OK
Preference-Applied: return; foo=bar
```

### ❌ Bad (1#applied-pref requires one non-empty member)

```http
GET / HTTP/1.1
Host: example.org
Prefer: return=representation

HTTP/1.1 200 OK
Preference-Applied: ,
```

### ❌ Bad (BWS around the '=' is admitted by the grammar and forbidden to senders)

```http
GET / HTTP/1.1
Host: example.org
Prefer: return=representation

HTTP/1.1 200 OK
Preference-Applied: return = representation
```
