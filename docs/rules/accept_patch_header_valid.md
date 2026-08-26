<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Accept-Patch Header

## Description

Checks the `Accept-Patch` response header field — its grammar wherever it appears, and the two responses RFC 5789 asks for it in.

**The grammar, on every response that carries the field.** `Accept-Patch = "Accept-Patch" ":" 1#media-type` (RFC 5789 §3.1), so every member is a media type: `type "/" subtype parameters` with each half a `token` and each parameter a `name=value` pair (RFC 9110 §8.3.1, §5.6.6). §3.1 hands the members off to "[RFC2616], Section 3.7", which is §8.3.1 today. The field is read on a response to any method, because §3.1 describes its presence "in response to any method" as an indication about the resource — an `Accept-Patch` sent in the OPTIONS response §3.1 asks for it in used to be validated by nothing at all. `1#` has a floor of one: `Accept-Patch:` and `Accept-Patch: ,` name no format and are the values §5.6.1.2 prints as invalid, while `Accept-Patch: text/example,` holds an empty member, which a sender MUST NOT generate (§5.6.1.1). Where the field appears on several lines in one section, the lines are one list (§5.2).

**Where the field is asked for, and where it is not.** Two sentences, both SHOULD:

- §2.2 — a `415 (Unsupported Media Type)` answering a `PATCH` "SHOULD include an Accept-Patch response header ... to notify the client what patch document media types are supported". A 415 is what a server sends when the client's format is one it does not support — but RFC 9110 §15.5.16 defines the status over the content's *coding* too, and a server refusing a coding has no patch format to name. The same section says such a server "ought to" send `Accept-Encoding`, so a 415 carrying that field stands this finding down. The residue is a 415 that was about a coding and named none; it is reported, and there is nothing in the message that says which of the two happened.
- §3.1 — "Accept-Patch SHOULD appear in the OPTIONS response for any resource that supports the use of the PATCH method". §3 says how a resource states that support: by listing the method in the `Allow` of that response. So the finding is an OPTIONS response whose `Allow` names `PATCH` and which carries no `Accept-Patch`. An `OPTIONS *` request is out: RFC 9110 §9.3.7 says such a request "applies to the server in general rather than to a specific resource", so its `Allow` states nothing about the resource §3.1's sentence is about. §3 leaves such a response's `Allow` listing conforming and names the cost — "the list of allowed patch documents is not advertised" — which the finding repeats rather than treating as an exemption; a SHOULD that no case could ever be measured against would be a sentence with nothing under it.

**Not reported: a successful `PATCH` response with no `Accept-Patch`.** This rule used to report every response to a `PATCH` that lacked the field. Nothing asks for it there. RFC 5789 §2.1's own worked example is a successful `PATCH` answered `204 No Content` with `Content-Location` and `ETag` and no `Accept-Patch`, so the document's first illustration of the method was a finding; a test runs it.

**Not reported: an asterisk.** `*` is a `tchar`, so `Accept-Patch: */*` derives from `media-type`, and this field's grammar contains no `media-range` for a wildcard to mean anything in. A server writing it has advertised a media type spelled with an asterisk. `patch_method_content_type_match` reports the request that reads it as permission.

**Not reported: which formats are advertised.** RFC 5789 defines no default patch document format and no registry of them, so no list of media types is the right one. Whether a `PATCH` request's `Content-Type` is among those advertised is `patch_method_content_type_match`'s question; whether a `PATCH` carrying content names its format at all is `patch_partial_update`'s.

Scope: responses only — §3.1 defines `Accept-Patch` as a response header, and an `Accept-Patch` in a request is measured by nothing here. A trailer section is not read: whether a field name may arrive as a trailer at all is §6.5.1's question, asked of every name at once by `message_trailer_fields_validity`. Method comparisons are exact, because the method token is case-sensitive (§9.1).

## Specifications

- [RFC 5789 §3.1](https://www.rfc-editor.org/rfc/rfc5789.html#section-3.1): The field: its grammar, its definition as a response header, its meaning in a response to any method, and the SHOULD that asks for it — in the OPTIONS response, not in the response to a PATCH. This reference said §2.2, which is Error Handling — and §2.2 turned out to hold a second SHOULD, listed below
- [RFC 5789 §3](https://www.rfc-editor.org/rfc/rfc5789.html#section-3): Advertising support in OPTIONS — how a resource says it supports PATCH, which is the antecedent §3.1's SHOULD needs, and the sentence that leaves an Allow listing conforming without the field while naming what its absence costs
- [RFC 5789 §2.2](https://www.rfc-editor.org/rfc/rfc5789.html#section-2.2): Error handling — the second SHOULD: a 415 answering a PATCH is told to carry the field, and what a 415 means is the whole of that requirement's condition
- [RFC 9110 §8.3.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.1): `media-type`, transcribed once in `helpers::headers` and shared with the Content-Type rule. It is where RFC 5789 §3.1's pointer at `[RFC2616], Section 3.7` resolves today; the obsolete name stays byte-exact inside the quote because it is the RFC's own wording
- [RFC 9110 §5.6.1.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.6.1.2): The list construct expanded, and the worked example naming the values a `1#` production rejects for holding no non-empty member. §5.6.1.1 is the sender's half — the empty-member finding
- [RFC 9110 §9.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.1): The method token is case-sensitive, which is why `PATCH` and `OPTIONS` are compared exactly and a `patch` request draws nothing from this rule
- [RFC 9110 §10.2.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.1): `Allow` — the value read to decide whether the OPTIONS response's resource supports PATCH. Its own grammar is `allow_header_method_tokens_valid`'s

## Configuration

```toml
[rules.accept_patch_header_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good §3.2's own OPTIONS exchange

```http
OPTIONS /example/buddies.xml HTTP/1.1
Host: www.example.com

HTTP/1.1 200 OK
Allow: GET, PUT, POST, OPTIONS, HEAD, DELETE, PATCH
Accept-Patch: application/example, text/example
```

### ✅ Good §2.1's own successful PATCH — nothing asks a response like this for the field

```http
PATCH /file.txt HTTP/1.1
Host: www.example.com
Content-Type: application/example

HTTP/1.1 204 No Content
Content-Location: /file.txt
ETag: "e0023aa4f"
```

### ✅ Good Two field lines in one section are one list

```http
HTTP/1.1 200 OK
Accept-Patch: application/example-patch+json
Accept-Patch: application/merge-patch+json
```

### ❌ Bad A member that is no media-type — there is no '/'

```http
HTTP/1.1 200 OK
Accept-Patch: badmedia
```

### ❌ Bad A `1#` list with no non-empty member names no format

```http
HTTP/1.1 200 OK
Accept-Patch: ,
```

### ❌ Bad A trailing comma is an empty member

```http
HTTP/1.1 200 OK
Accept-Patch: application/example,
```

### ❌ Bad §2.2's SHOULD — a 415 answering a PATCH says which formats it takes

```http
PATCH /file.txt HTTP/1.1
Host: www.example.com
Content-Type: application/example

HTTP/1.1 415 Unsupported Media Type
```

### ❌ Bad §3.1's SHOULD — the resource advertises PATCH and not its formats

```http
OPTIONS /example/buddies.xml HTTP/1.1
Host: www.example.com

HTTP/1.1 200 OK
Allow: GET, PUT, POST, OPTIONS, HEAD, DELETE, PATCH
```
