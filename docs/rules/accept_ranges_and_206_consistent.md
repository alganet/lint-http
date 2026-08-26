<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Accept Ranges And 206 Consistent

## Description

Advice about one field, and one contradiction. `Accept-Ranges` tells a client which range units a resource supports, and a 206 (Partial Content) response is proof that it supports at least one — so what the two say together is worth reading, even though almost none of it is required.

**No `Accept-Ranges` on a 206** is reported as advice rather than as a violation. RFC 9110 §14.3 says a client "MAY generate range requests regardless of having received an Accept-Ranges field" and that the field "only provides advice for the sake of improving performance and reducing unnecessary network transfers"; §14 makes range requests an OPTIONAL feature of HTTP altogether. A server that omits the field is conforming, and this rule used to describe it as a SHOULD that no sentence supports. §15.3.7 does list the header fields a 206 MUST carry — Date, Cache-Control, ETag, Expires, Content-Location and Vary — and `Accept-Ranges` is not one of them.

**`Accept-Ranges: none` on a 206** is the contradiction. The permission to send `none` is granted to "a server that does not support any kind of range request for the target resource", and a 206 is that server successfully fulfilling one. The range unit `none` is reserved for saying that, so it is reported when it travels beside a real unit as well as when it stands alone.

**A `Content-Range` unit the field does not advertise** sits on the same advisory footing as the first finding: a 206 is sent when the request's range unit is supported for the target resource (§14.2), so an advertisement that leaves that unit out is incomplete advice, not a violation.

**The trailer section counts.** §14.3 permits `Accept-Ranges` in a trailer section — the rule reads both sections, so a response that advertises after its content is not reported for advertising nothing.

**Not this rule's findings.** Whether the value is a well-formed list of range units belongs to `accept_ranges_values_valid`; whether a 206 carries a `Content-Range` at all, and whether that value parses, belong to `message_range_and_content_range_consistency`. Where a field line cannot be read as range units — an octet outside US-ASCII, a character `token` excludes, a list with no elements — this rule declines rather than reporting the field a second time, and stays quiet about a unit it may not have seen. A value it cannot read is still counted as present: the message on the wire carries the field.

## Specifications

- [RFC 9110 §14.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.3): `Accept-Ranges`: `1#range-unit`, advertising which units a resource supports, or `none`. Sending it is not required — the section says so twice — and it MAY be sent in a trailer section
- [RFC 9110 §15.3.7](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.3.7): `206 Partial Content`: the server successfully fulfilling a range request, which is what makes `Accept-Ranges: none` in the same response a contradiction. The section also lists the header fields a 206 MUST carry, and `Accept-Ranges` is not among them. RFC 7233 §4.1 defined the status code; RFC 9110 obsoleted RFC 7233
- [RFC 9110 §14.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.2): `Range`: a 206 is the answer when the request's range unit is supported for the target resource, so the `Content-Range` unit is a unit the server supports
- [RFC 9110 §14.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-14.1): Range units: `range-unit = token`, one construct shared by `Accept-Ranges`, `Range` and `Content-Range`, and case-insensitive — which is why both sides of the comparison are folded

## Configuration

```toml
[rules.accept_ranges_and_206_consistent]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 206 Partial Content
Content-Range: bytes 0-499/1234
Accept-Ranges: bytes
```

### ✅ Good — unit names are case-insensitive

```http
HTTP/1.1 206 Partial Content
Content-Range: bytes 0-499/1234
Accept-Ranges: BYTES
```

### ✅ Good — one list split across two field lines

```http
HTTP/1.1 206 Partial Content
Content-Range: bytes 0-499/1234
Accept-Ranges: pages
Accept-Ranges: bytes
```

### ❌ Bad — `none` contradicts the 206 that fulfilled a range request

```http
HTTP/1.1 206 Partial Content
Content-Range: bytes 0-499/1234
Accept-Ranges: none
```

### ❌ Bad — advice: no field to resume from

```http
HTTP/1.1 206 Partial Content
Content-Range: bytes 0-499/1234
```

### ❌ Bad — advice: the unit served is not among those advertised

```http
HTTP/1.1 206 Partial Content
Content-Range: bytes 0-499/1234
Accept-Ranges: pages
```
