<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Prefer, Preference-Applied and the Vary a cache needs

## Description

Reports a response that states a preference was applied — `Preference-Applied` naming one of the four preferences RFC 7240 defines — without the `Vary` that §2 requires of a server whose preferences affect caching: *"If a server supports the optional application of a preference that might result in a variance to a cache's handling of a response entity, a Vary header field MUST be included in the response listing the Prefer header field regardless of whether the client actually used Prefer in the request."* §2 admits `Vary: *` as the alternative, and either spelling satisfies the rule.

**The trigger is the response, not the request.** A `Prefer` request header says what a client asked for and nothing about what the server supports; a `Preference-Applied` response header is the server stating that it applies that preference. That is the half of the sentence's antecedent a captured exchange can establish, and it is what the *"regardless of whether the client actually used Prefer in the request"* clause points at.

**Only GET and HEAD.** The requirement is conditioned on a variance to *a cache's* handling of the entity, and a single exchange shows that only where a cache would store the response under the target URI alone. POST is a cacheable method but its responses become storable only with explicit freshness information and a `Content-Location` (RFC 9110 §9.3.3), so `Preference-Applied` on a POST is not by itself evidence that anything is stored — which is why RFC 7240 §4.2's own `POST /collection` example and §3's own `PATCH` example are not findings here.

**Only the four preferences RFC 7240 defines.** `return` decides whether the response carries a representation or as little as the server can send (§4.2); `respond-async` and `wait` decide whether the response is the result or a 202 standing in for it (§4.1, §4.3); `handling` decides whether a request the server could still process is rejected with a 4xx (§4.4). Each of those is a variance the document itself describes. A preference registered elsewhere has its effect written in its own registration (§5.1), so whether it varies the entity is not readable here and the rule stays silent rather than invent the antecedent of a MUST.

**What this rule does not report, and why.** A response that omits `Preference-Applied` after a `Prefer` request is not a finding. §3 makes the field a MAY; §2 says outright that *"servers are allowed to ignore stated preferences"*, so silence may correctly mean nothing was applied; and §3's own next sentence narrows it further — *"Use of the Preference-Applied header is only necessary when it is not readily and obviously apparent that a server applied a given preference and such ambiguity might have an impact on the client's handling of the response."* — a condition about what a client application can determine, which no message states. RFC 7240 §4.2's two example responses honor `return` and carry no `Preference-Applied` at all.

**The boundary.** §2's MUST binds a server that *supports* applying such a preference, whether or not it applied one here and whether or not the client asked. The only in-message evidence of that support is `Preference-Applied`, and §3 leaves a server free to apply a preference and say nothing — so a server that varies its responses silently is outside what any single capture can show. `prefer_header_valid` reads the request's field against its grammar and `preference_applied_header_valid` reads the response's against its own and against what was asked for; neither looks at `Vary`.

## Specifications

- [RFC 7240 §2](https://www.rfc-editor.org/rfc/rfc7240.html#section-2): The `Vary` MUST this rule enforces, its `Vary: *` alternative, the case rule for comparing preference token names, and the statement that servers are allowed to ignore stated preferences — which is why a missing `Preference-Applied` is not a finding
- [RFC 7240 §3](https://www.rfc-editor.org/rfc/rfc7240.html#section-3): `Preference-Applied` — a MAY, with its grammar, and the sentence narrowing its use to the case where a client could not otherwise tell that a preference was applied. The field's presence is this rule's evidence, not its requirement
- [RFC 7240 §4](https://www.rfc-editor.org/rfc/rfc7240.html#section-4): What each of the four defined preferences does to the response, which is what makes it one that "might result in a variance to a cache's handling of a response entity": §4.1 and §4.3 (a 202 in place of the result), §4.2 (a representation or a minimal answer), §4.4 (a 4xx in place of processing)
- [RFC 7240 §5.1](https://www.rfc-editor.org/rfc/rfc7240.html#section-5.1): The "HTTP Preferences" registry keeps a preference's effect in its own registration, which is why a name RFC 7240 does not define is left unjudged rather than assumed to vary the entity
- [RFC 9110 §12.5.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.5): `Vary = #( "*" / field-name )` — a list field, read across its lines, whose members are field names and so compared case-insensitively
- [RFC 9110 §9.2.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2.3): Which methods have caching semantics. With §9.3.3's condition on POST responses, this is why the gate is GET and HEAD — the methods where one exchange shows a cache would hold the response under the target URI alone
- [RFC 9110 §9.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.1): The method token is case-sensitive, so the gate compares the octets as written rather than folding an unrecognized method into GET
- [RFC 9111 §4.1](https://www.rfc-editor.org/rfc/rfc9111.html#section-4.1): What the `Vary` this rule asks for buys: without it a stored response is matched on the target URI alone, and the request field that selected it is not part of the key

## Configuration

```toml
[rules.prefer_header_and_preference_applied]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good (the applied preference is named, and Vary makes it part of the cache key)

```http
GET /my-document HTTP/1.1
Host: example.org
Prefer: return=minimal

HTTP/1.1 200 OK
Content-Type: application/json
Preference-Applied: return=minimal
Vary: Prefer
```

### ✅ Good (RFC 7240 §2's alternative spelling)

```http
GET /my-document HTTP/1.1
Host: example.org
Prefer: respond-async

HTTP/1.1 200 OK
Preference-Applied: respond-async
Vary: *
```

### ✅ Good (RFC 7240 §3's own example — a PATCH response is not one a cache holds under the target URI)

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

### ✅ Good (a preference registered elsewhere; RFC 7240 does not say what applying it changes)

```http
GET /my-document HTTP/1.1
Host: example.org
Prefer: depth-noroot

HTTP/1.1 200 OK
Preference-Applied: depth-noroot
```

### ❌ Bad (the server states it varied the entity and left it out of the cache key)

```http
GET /my-document HTTP/1.1
Host: example.org
Prefer: return=minimal

HTTP/1.1 200 OK
Content-Type: application/json
Preference-Applied: return=minimal
```

### ❌ Bad (Vary is present but does not list Prefer)

```http
GET /my-document HTTP/1.1
Host: example.org
Prefer: return=representation

HTTP/1.1 200 OK
Content-Type: application/json
Preference-Applied: return=representation
Vary: Accept-Encoding
```
