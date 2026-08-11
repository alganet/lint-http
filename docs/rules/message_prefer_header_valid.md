<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Prefer header syntax

## Description

Reads a request's `Prefer` field against RFC 7240 §2's grammar — `Prefer = 1#preference`, `preference = token [ BWS "=" BWS word ] *( OWS ";" [ OWS parameter ] )`, `parameter = token [ BWS "=" BWS word ]` — and against the productions §4 writes for the four preferences it defines.

**The field is read as one list of octets.** A client MAY spread its preferences over several `Prefer` field lines, and §2 says that is equivalent to one field carrying their comma-separated concatenation, so the lines are joined before the members are counted and a member written at a line boundary is one member. The value is not decoded: a `word` may be a `quoted-string`, `qdtext` admits `obs-text`, and refusing the field over an octet above %x7E would hide the legal value and the illegal one alike. Commas and semicolons inside a `quoted-string` are `qdtext` and not separators.

**`1#preference` requires one non-empty member.** `Prefer:`, `Prefer: ,` and `Prefer: ,   ,` are three spellings of the same defect, and an empty element beside a real one is §5.6.1.1's separate sender MUST NOT. A bare `;` is *not* one: §2 writes the parameter inside an optional bracket, so `foo; ; bar` derives from the grammar as written.

**A value is a `word`, and `word` is `token / quoted-string`.** Neither derives the empty string, so `foo=` matches nothing — the spelling for a preference with no value is `foo`, or `foo=""`, which §2 says means the same thing. The quoting is not part of the value: `return="minimal"` and `return=minimal` are the same preference.

**The four preferences RFC 7240 defines are checked against their own productions.** `respond-async` is the token alone and admits no value; `return` admits `representation` or `minimal`; `handling` admits `strict` or `lenient`; `wait` admits a `delta-seconds`, which is `1*DIGIT` and so has no sign and no decimal point. RFC 7240 states no requirement about any of these values — it writes the grammar and stops — so what makes a value outside them a finding is RFC 9110 §2.2's MUST NOT on generating elements that do not match the corresponding ABNF. The comparison folds case because an ABNF string literal matches any case (RFC 5234 §2.3); §2's rule that *values* are case sensitive decides whether two values written in two messages are the same value, which is `message_preference_applied_header_valid`'s question and not this one's.

**Any other preference name is left alone.** The "HTTP Preferences" registry is open, and §5.1's template puts a registered preference's admitted values in its own registration — so the value of a preference defined elsewhere is not readable from RFC 7240, and §2 requires a server that cannot place a token to ignore it rather than signal an error. Parameters are not judged beyond their grammar for the same reason: §2 makes their meaning depend on the preference's own definition.

**A repeated preference token is reported.** §2 asks clients not to write one twice and says the first instance is the one considered, so the second is text no recipient acts on; §4.2 and §4.4 add that `return` and `handling` written twice can cost the client both instances.

**Not decided here:** whether the server honored anything — `message_preference_applied_header_valid` compares this field against the response's `Preference-Applied`, and `client_prefer_header_and_preference_applied` reports a response that carries none. Nor §2's `Vary` MUST, which is conditioned on whether a server *supports* applying a preference in a way that affects caching — a fact about the server that no captured message states.

## Specifications

- [RFC 7240 §2](https://www.rfc-editor.org/rfc/rfc7240.html#section-2): `Prefer` — the grammar, the equivalence of several field lines with one, the equivalence of an empty value with no value, the case rules for names and values, the SHOULD NOT against repeating a token, and the server's MUST to ignore a preference it does not recognize
- [RFC 7240 §4](https://www.rfc-editor.org/rfc/rfc7240.html#section-4): The four preferences this document defines, each with its own production: `respond-async` (§4.1), `return` (§4.2), `wait` (§4.3) and `handling` (§4.4). §4.2 and §4.4 add that the two values of `return` and of `handling` are mutually exclusive
- [RFC 7240 §5.1](https://www.rfc-editor.org/rfc/rfc7240.html#section-5.1): The "HTTP Preferences" registry is open under Specification Required, and a registration carries its own enumeration of admitted values — which is why a preference RFC 7240 does not define has its value left unjudged here
- [RFC 7240 §1.1](https://www.rfc-editor.org/rfc/rfc7240.html#section-1.1): Where `token`, `word`, `OWS`, `BWS`, the `#rule` extension and `delta-seconds` come from. The named sources are RFC 7230 and RFC 7231, which RFC 9110 obsoletes; `word` is the one name RFC 9110 did not keep, and the `delta-seconds` pointer is wrong twice over — RFC 7231 §8.1.3 is a registration procedure, and RFC 7231 does not define `delta-seconds` anywhere. It was RFC 7234 §1.2.1's, and the live definition is RFC 9111 §1.2.2
- [RFC 9110 §2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2): The MUST NOT on generating a protocol element that does not match its ABNF — what makes a value outside a §4 production a finding, since RFC 7240 writes those productions and states no requirement about them
- [RFC 9110 §5.6.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1): The `#rule` extension: §5.6.1.1 forbids the sender an empty list element, §5.6.1.2 prints the values a `1#` production rejects for having no non-empty member
- [RFC 9110 §5.6.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.3): `BWS`: a recipient must remove it before interpreting the element, and a sender must not have written it — both directions are read at the `=` in `preference` and in `parameter`
- [RFC 9111 §1.2.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-1.2.2): `delta-seconds = 1*DIGIT` — what the `wait` preference's value has to be
- [RFC 5234 §2.3](https://www.rfc-editor.org/rfc/rfc5234.html#section-2.3): An ABNF string literal matches any case, which is why `return=Minimal` is not reported against §4.2's `"minimal"`

## Configuration

```toml
[rules.message_prefer_header_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good (RFC 7240 §2's own example of three preferences over two field lines)

```http
POST /foo HTTP/1.1
Host: example.org
Prefer: respond-async, wait=100
Prefer: handling=lenient
Date: Tue, 20 Dec 2011 12:34:56 GMT
```

### ✅ Good (a parameter, and a quoted-string carrying the grammar's own delimiters)

```http
POST /items HTTP/1.1
Host: example.org
Prefer: return=representation; foo="a,b;c"
```

### ✅ Good (`foo`, `foo=""` and a bare `;` all derive from the grammar)

```http
POST /items HTTP/1.1
Host: example.org
Prefer: respond-async; bar=""; ; baz
```

### ❌ Bad (`word` is `token / quoted-string`; neither derives the empty string)

```http
POST /items HTTP/1.1
Host: example.org
Prefer: return=
```

### ❌ Bad (`return` admits only "representation" or "minimal")

```http
POST /items HTTP/1.1
Host: example.org
Prefer: return=whatever
```

### ❌ Bad (`wait` takes a delta-seconds, which has no sign)

```http
POST /items HTTP/1.1
Host: example.org
Prefer: wait=-1
```

### ❌ Bad (`respond-async` is the token alone and defines no value)

```http
POST /items HTTP/1.1
Host: example.org
Prefer: respond-async=1
```

### ❌ Bad (only the first instance of a preference is considered)

```http
POST /items HTTP/1.1
Host: example.org
Prefer: return=minimal, return=representation
```

### ❌ Bad (BWS around the '=' is admitted by the grammar and forbidden to senders)

```http
POST /items HTTP/1.1
Host: example.org
Prefer: return = minimal
```

### ❌ Bad (1#preference requires one non-empty member)

```http
POST /items HTTP/1.1
Host: example.org
Prefer: ,
```
