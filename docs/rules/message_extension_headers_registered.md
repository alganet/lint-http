<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_extension_headers_registered

## Description

Non-standard or extension header field-names (i.e., those not registered in the IANA HTTP Field Name registry) SHOULD be explicitly allowed by configuration to avoid accidental custom headers, typos, and interoperability issues. This rule flags header field-names that are not present in the rule's `allowed` list.

## Specifications

- [RFC 9110 §5.1 — Field names](https://www.rfc-editor.org/rfc/rfc9110.html#section-5.1)
- [IANA HTTP Field Name Registry](https://www.iana.org/assignments/http-field-names/http-field-names.xhtml)

## Configuration

This rule **requires** an `allowed` array listing permitted header field-names (case-insensitive). Example:

```toml
[rules.message_extension_headers_registered]
enabled = true
severity = "warn"
allowed = ["host", "content-type", "user-agent", "x-custom"]
```

The `allowed` list should include standard header names you accept as registered as well as any intentional extension headers (e.g., vendor or app-specific headers).

## Examples

### ✅ Good

```http
Host: example.com
Content-Type: text/plain
X-Custom: 1
```

### ❌ Bad

```http
X-Custome: 1   # typo or unregistered header not allowed
X-Unknown: 2   # unregistered header not in allowed list
```
