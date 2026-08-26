<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Host and :authority Consistency

## Description

Reports an HTTP/2 or HTTP/3 request whose `Host` header field and `:authority` pseudo-header field do not name the same authority.

**Two documents state this requirement, and neither is a copy of the other.** RFC 9113 §8.3.1: "Clients MUST NOT generate a request with a Host header field that differs from the \":authority\" pseudo-header field." — followed by what such a message costs: "A server SHOULD treat a request as malformed if it contains a Host header field that identifies an entity that differs from the entity in the \":authority\" pseudo-header field." RFC 9114 §4.3.1 puts it as a property of the request: "If both fields are present, they MUST contain the same value." A mismatch is a routing disagreement inside one message — whichever field a recipient trusts decides which resource it serves, which is why this shape turns up in request-smuggling and cache-poisoning reports. Each finding is worded from the document that governs the version it was found on.

**The two versions do not define the comparison the same way, and this rule does not harmonise them.** RFC 9113 continues: "The values of fields need to be normalized to compare them (see Section 6.2 of [RFC3986]). An origin server can apply any normalization method, whereas other servers MUST perform scheme-based normalization (see Section 6.2.3 of [RFC3986]) of the two fields." RFC 9114 asks for the same value and names no normalization — the word appears nowhere in that document. So over **HTTP/2** two values that normalization makes one authority are the same value and are not reported, while over **HTTP/3** they are reported, with the finding printing the normal form both share and saying which sentence decided it. A difference no normalization removes is reported on both.

**What scheme-based normalization is here.** RFC 9110 §4.2.3 is where the steps for an "http" or "https" URI are written down, and this rule performs the three that can apply to an authority: a port equal to the scheme's default is omitted, the host is compared without regard to case, and a percent-encoded octet standing for an unreserved character is decoded ("Characters other than those in the 'reserved' set are equivalent to their percent-encoded octets"). The fourth step is about a path component, which an authority does not have. So over HTTP/2 `example.com:443` and `example.com` on an `https` request are one authority, and so are `Example.COM` and `example.com`, and `exam%70le.com` and `example.com`.

**What is never folded.** The same sentence says "all other components are compared in a case-sensitive manner", so a userinfo subcomponent is carried through as written. Both versions forbid one in an `:authority` only **for "http" and "https" schemed URIs**, and both say `:scheme` is not restricted to those two — so an authority under another scheme may carry userinfo, and its case is part of it. Where a userinfo does appear under `http` or `https`, `http2_pseudo_headers_valid` reports it; the HTTP/3 pseudo-header rule does not check it today.

**An empty `Host` beside an `:authority`** is a difference like any other and is reported on both versions. RFC 9114 §4.3.1 also states it outright — "If these fields are present, they MUST NOT be empty" — though that sentence's antecedent is a request whose `:scheme` identifies a scheme with a mandatory authority component, which a CONNECT does not send.

**Not reported, because the two fields are not both there.** A request whose target carries no authority is nothing to compare against, and whether it should have carried one is a question about the pseudo-header itself — `http2_pseudo_headers_valid` and `http3_pseudo_headers_valid` own it. A request with no `Host` field is the other half of §4.3.1's either-or and is `host_header`'s question. A request with **two** `Host` field lines names no single authority: `Host` is not a list field, so RFC 9110 §5.3 forbids the repetition and `host_header` reports the message.

**Not reported: an asterisk-form OPTIONS.** The capture records the target as the string form of a URI rebuilt from the pseudo-headers, and a `:path` of `*` leaves no delimiter before it — `https://example.com*` is what both an `OPTIONS *` for `example.com` and an origin whose name ends in `*` come back as, since `*` is a `sub-delims` character a `reg-name` admits. An `OPTIONS` whose recorded authority ends in `*` is therefore left alone rather than reported for a difference the capture invented.

**Not reported: whether either value is a well-formed authority.** `Host = uri-host [ ":" port ]` is `host_header`'s check, and the `:authority`'s shape — its userinfo, and the port a CONNECT must name — belongs to the pseudo-header rule for each version. This rule asks only whether the two agree, so two values that are equally malformed agree and are silent here.

**Scope and version.** Only HTTP/2 and HTTP/3 requests are measured, because only they have an `:authority` (RFC 9110 §7.2). That is not a narrowing of the requirement: over HTTP/1.1 an absolute-form request-target carries an authority beside a `Host` too, and RFC 9112 §3.2.2 answers that pair the other way round — "the origin server MUST ignore the received Host header field (if any) and instead use the host information of the request-target", with a proxy told to replace it. There the disagreement is a recipient's to resolve, not a sender's defect.

**Where the values come from, and what that costs on HTTP/3.** A capture records the request target as the URI these versions reassemble. Over HTTP/2 the authority in it is the `:authority` and nothing else — the library this proxy uses builds it from that pseudo-header alone and never reads `Host`. **Over HTTP/3 it is not**: that library takes the authority from the `Host` field when both are present, and rejects the request at the transport when the two differ as strings. So no HTTP/3 mismatch this proxy captured itself can reach this rule, and its HTTP/3 findings are for captures written by other tools and read back through `lint` — while the same transport's byte comparison is itself a reading of RFC 9114's "same value" that agrees with this rule's. The `Host` field is read as octets rather than through a UTF-8 decode, so a value carrying `obs-text` is compared rather than skipped.

## Specifications

- [RFC 9113 §8.3.1](https://www.rfc-editor.org/rfc/rfc9113.html#section-8.3.1): HTTP/2's half: the client's MUST NOT, the server's SHOULD-treat-as-malformed, and the two sentences that define the comparison over *normalized* values — which is why a default or empty port is not a difference on this version
- [RFC 9114 §4.3.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.3.1): HTTP/3's half: both fields present MUST contain the same value and MUST NOT be empty, with no normalization named anywhere in the document — the sentence that makes one pair of values conforming over HTTP/2 and malformed here
- [RFC 9110 §4.2.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.3): What scheme-based normalization involves for an "http" or "https" URI — the default port, the case of the host, the percent-encoded unreserved character, and the sentence that keeps every other component case-sensitive
- [RFC 3986 §6.2.2.1](https://www.rfc-editor.org/rfc/rfc3986.html#section-6.2.2.1): Case normalization — including the hexadecimal digits of a percent-encoding triplet, which is why a triplet that stays encoded is still put in one form
- [RFC 3986 §6.2.2.2](https://www.rfc-editor.org/rfc/rfc3986.html#section-6.2.2.2): Percent-encoding normalization — decode any triplet standing for an unreserved character
- [RFC 3986 §6.2.3](https://www.rfc-editor.org/rfc/rfc3986.html#section-6.2.3): Scheme-based normalization, and the sentence that keeps an empty delimiter where no scheme licenses removing it — which is why nothing is elided from an authority-form target
- [RFC 9110 §4.2.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.1): The default port for an "http" URI is 80 — one of the two numbers scheme-based normalization needs, and the reason the scheme is read from the recorded target rather than assumed
- [RFC 9110 §4.2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-4.2.2): The default port for an "https" URI is 443
- [RFC 9110 §7.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.2): Which versions carry the two fields at once: in HTTP/2 and HTTP/3 the `Host` field is supplanted by `:authority`, which is why the rule is gated to those two
- [RFC 9112 §3.2.2](https://www.rfc-editor.org/rfc/rfc9112.html#section-3.2.2): Why HTTP/1.1 is not measured: an absolute-form target beside a `Host` is answered by having the recipient ignore the field, not by calling the sender wrong

## Configuration

```toml
[rules.host_and_authority_consistent]
enabled = true
severity = "error"
```

## Examples

### ✅ Good The two fields carry one authority

```http
:method: GET
:scheme: https
:authority: example.com
:path: /resource
host: example.com
```

### ✅ Good HTTP/2 only — the values are compared normalized, and scheme-based normalization elides an "https" default port

```http
:method: GET
:scheme: https
:authority: example.com:443
:path: /resource
host: example.com
```

### ✅ Good HTTP/2 only — the host is compared without regard to case, and a triplet standing for an unreserved character is decoded

```http
:method: GET
:scheme: https
:authority: Example.COM
:path: /resource
host: exam%70le.com
```

### ❌ Bad HTTP/3 only — the same default port, where the document asks for the same value and names no normalization

```http
:method: GET
:scheme: https
:authority: example.com:443
:path: /resource
host: example.com
```

### ✅ Good A CONNECT's authority-form target, matched exactly

```http
:method: CONNECT
:authority: example.com:443
host: example.com:443
```

### ❌ Bad Two authorities in one request — the routing disagreement

```http
:method: GET
:scheme: https
:authority: example.com
:path: /resource
host: other.example
```

### ❌ Bad A port neither scheme defaults to is part of the authority

```http
:method: GET
:scheme: https
:authority: example.com:8080
:path: /resource
host: example.com:9090
```

### ❌ Bad Both fields present, one of them naming no authority

```http
:method: GET
:scheme: https
:authority: example.com
:path: /resource
host:
```
