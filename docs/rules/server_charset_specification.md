<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Server Charset Specification

## Description

This rule checks if `Content-Type` headers for text-based resources (starting with `text/`) include a `charset` parameter. Responses only, and the type is matched case-insensitively, so `TEXT/HTML` is in scope.

Specifying the character encoding is crucial for security and correct rendering. If the charset is not explicitly defined, browsers may attempt to guess the encoding (MIME sniffing), which can lead to Cross-Site Scripting (XSS) vulnerabilities or incorrect display of characters.

No specification requires the parameter — RFC 9110 defines what `charset` means and mandates nothing about sending it — so this rule is a deliberate policy rather than a conformance check. Only the parameter's presence is checked; whether its value names a registered charset is a separate rule's concern.

## Specifications

- [RFC 9110 §8.3.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.1): `media-type` and the case-insensitivity of its type/subtype tokens, which decides what counts as `text/*` here
- [RFC 9110 §8.3.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.2): What `charset` is for. Note it mandates nothing: no requirement to send the parameter exists, so flagging its absence is this linter's policy
- [MDN Content-Type](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Type): Content-Type

## Configuration

```toml
[rules.server_charset_specification]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good Response

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
```

### ❌ Bad Response

```http
HTTP/1.1 200 OK
Content-Type: text/html
# Missing charset parameter
```
