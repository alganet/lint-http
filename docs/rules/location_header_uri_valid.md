<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Location Header URI Valid

## Description

Validates the `Location` response header field's value against its own production, `Location = URI-reference` (RFC 9110 §10.2.2), which is RFC 3986 §4.1's `URI-reference` — a URI or a relative reference, and nothing else.

Every finding here except one is a violation rather than advice, and the sentence that makes it so is RFC 9110 §2.2's — *"A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules"* — not anything in §10.2.2, which defines the field and forbids nothing about it. That is why *where* a `Location` may appear is advisory (`redirect_status_and_location_valid`) while *what it may say* is not.

The field is a **singleton**: its grammar has no comma-separated-list form, so a message carries at most one `Location` field line (RFC 9110 §5.3), and two lines are reported as that. The detection is a count of the lines rather than the join used for every other singleton, and the reason is in §10.2.2's own Note: the comma a recipient recombines field lines with is a valid data character inside a URI-reference, so joining two `Location` lines yields a *well-formed* reference — to neither of the resources the sender named. Recovering the intended value from that is, in the RFC's words, difficult and not interoperable.

Every octet is measured rather than skipped, and the finding names the octet. This is not a UTF-8 question: a URI is composed from `unreserved`, `gen-delims` and `sub-delims` characters plus `pct-encoded` triplets (RFC 3986 §2), so `obs-text` is reported for not being a URI character, which is what is wrong with it. So are `SP`, `"`, `<`, `>`, `\`, `^`, `` ` ``, `{`, `|`, `}` and every control character — each has to be percent-encoded before the URI is formed. Leading and trailing whitespace is excluded before the value is evaluated (RFC 9110 §5.5), and only `SP`/`HTAB` count as that.

A `%` must open a well-formed `pct-encoded` triplet, and a value that carries a scheme must carry a `scheme` (RFC 3986 §3.1).

**One finding here is advice rather than a violation, and is labelled as such in its own message: an empty value.** An empty `URI-reference` is legal — `relative-part` admits `path-empty`, making it a same-document reference that resolves to the target URI (RFC 3986 §4.4) — so no sentence forbids `Location:` with nothing after it. It is reported because a sender writing the field means to name a resource and has named the one the client already had.

**Scope: this rule reads the field's syntax and nothing else.** Whether a given status code may carry a `Location` at all is `redirect_status_and_location_valid`'s finding, and whether a redirect status arrived without one is `location_on_redirect_present`'s; both are asked of every status, so no status gate is applied here. §10.2.2's requirement that a 3xx `Location` with no fragment component inherit the fragment of the reference that generated the target URI is addressed to the *user agent* processing the redirect, not to the sender, so no captured message can be measured against it. Only the header section is read: whether any field at all may be sent in a *trailer* section is RFC 9110 §6.5.1's deny-by-default question and `trailer_fields_valid`'s finding.

## Specifications

- [RFC 9110 §10.2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.2): Location: the field definition, `Location = URI-reference`, and the Note explaining why the field cannot be a list — the comma list separator is valid data inside a URI-reference
- [RFC 9110 §2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2): Conformance: a sender MUST NOT generate a protocol element that does not match its ABNF. This is what makes a malformed `Location` value a violation, since §10.2.2 itself forbids nothing
- [RFC 9110 §5.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.3): Field Order: a sender MUST NOT generate multiple field lines for a field with no comma-separated-list alternative. `Location` has none, so two lines are reported
- [RFC 9110 §5.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.5): Field Values: singleton fields, the care a comma needs in a field carrying a URI-reference, and the MUST to exclude leading and trailing whitespace before evaluating a field value
- [RFC 3986 §2](https://www.rfc-editor.org/rfc/rfc3986.html#section-2): Characters: the limited set a URI is composed from — `unreserved`, `gen-delims`, `sub-delims` — and the `pct-encoded` triplet every other octet must be written as
- [RFC 3986 §4.1](https://www.rfc-editor.org/rfc/rfc3986.html#section-4.1): `URI-reference = URI / relative-ref`. §4.4 is why an empty value is one of them, and so why the empty-value finding here is advisory

## Configuration

```toml
[rules.location_header_uri_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good (absolute URI)

```http
HTTP/1.1 302 Found
Location: https://example.com/new-location
```

### ✅ Good (relative URI-reference)

```http
HTTP/1.1 302 Found
Location: /new-location?ref=1
```

### ✅ Good (a comma is a sub-delim, so it is ordinary data here)

```http
HTTP/1.1 302 Found
Location: /archive/1996,1997
```

### ❌ Bad (two field lines — `Location` is a singleton, and joining them yields a valid reference to neither)

```http
HTTP/1.1 302 Found
Location: /first
Location: /second
```

### ❌ Bad (empty value — advice, not a violation: it resolves to the target URI)

```http
HTTP/1.1 302 Found
Location:
```

### ❌ Bad (invalid percent-encoding)

```http
HTTP/1.1 302 Found
Location: /bad%2Gencoding
```

### ❌ Bad (SP is not a URI character; it has to be written `%20`)

```http
HTTP/1.1 302 Found
Location: https://example.com/ bad
```
