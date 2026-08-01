<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Content Encoding And Type Consistency

## Description

Validate `Content-Encoding` header members for common correctness issues: members must be valid `token`s, a wildcard `*` is rejected (it belongs to `Accept-Encoding`), and a coding repeated within the field is flagged.

Responses that carry no content (1xx, 204, 304) are flagged for sending `Content-Encoding` at all. For 304 this follows RFC 9110 §15.4.5, which tells a sender not to include representation metadata beyond a listed set; for 1xx and 204 it is this rule's inference that a coding describing absent content is a misconfiguration.

Repeating a coding is likewise a judgement call rather than a conformance failure — `gzip, gzip` legitimately expresses gzip applied twice — but in practice it usually means two layers each added the header.

**Note:** despite the rule's name, no `Content-Type` consistency check is performed; the rule inspects `Content-Encoding` only.

## Specifications

- [RFC 9110 §8.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.4): `Content-Encoding = #content-coding` — the list the member checks walk. Note it does not forbid repeating a coding, so the duplicate check is this rule's judgement
- [RFC 9110 §15.4.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.4.5): Why a 304 should not carry Content-Encoding: a sender SHOULD NOT include representation metadata beyond the listed fields. (This reference previously pointed at §8.3, which is Content-Type, not message-body rules.) The 1xx and 204 cases have no such sentence and are inferred

## Configuration

```toml
[rules.message_content_encoding_and_type_consistency]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
HTTP/1.1 200 OK
Content-Encoding: gzip, br
Content-Type: application/json; charset=utf-8

...compressed JSON body...
```

### ❌ Bad (duplicate coding)

```http
HTTP/1.1 200 OK
Content-Encoding: gzip, gzip
Content-Type: application/json

...compressed JSON body...
```

### ❌ Bad (Content-Encoding on no-body response)

```http
HTTP/1.1 204 No Content
Content-Encoding: gzip
```
