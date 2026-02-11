<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->
# message_content_md5_vs_digest_preference

## Description

If both legacy `Content-MD5` and modern `Content-Digest` are present in the same message, prefer validating and using `Content-Digest`. `Content-MD5` is deprecated by newer specifications (see RFC 9530) and may not carry the same algorithm flexibility or security guarantees.

This rule flags messages (requests or responses) that include both `Content-Digest` (RFC 9530 structured digest) and the legacy `Content-MD5` header. When both are present, `Content-Digest` should be preferred for integrity validation and `Content-MD5` should be avoided because it is deprecated.

## Specifications

- [RFC 9530 §2–§4 — Content-Digest and related structured fields](https://www.rfc-editor.org/rfc/rfc9530.html)
- [RFC 7231 §3.3.2 — Content-MD5 (historical reference)](https://www.rfc-editor.org/rfc/rfc7231.html#section-3.3.2)

## Configuration

```toml
[rules.message_content_md5_vs_digest_preference]
enabled = true
severity = "warn"
```

Only `enabled` and `severity` are required for this rule.

## Examples

### ✅ Good

```http
Content-Digest: sha-256=":dGVzdA==:"
```

### ❌ Bad

```http
Content-Digest: sha-256=":dGVzdA==:"
Content-MD5: dGVzdA==
```
