<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Content Md5 Vs Digest Preference

## Description

This rule flags messages (requests or responses) that carry both `Content-Digest` (the RFC 9530 structured field) and the legacy `Content-MD5` header.

Carrying both is a hazard in its own right: they are independent integrity values over the same content, computed by different algorithms, and no specification says which one a recipient validates — so a mismatch between them has no defined resolution.

`Content-MD5` should simply be dropped. It is not merely discouraged but absent from HTTP: RFC 7231 removed it, for being inconsistently implemented with respect to partial responses. (RFC 9530, which defines `Content-Digest`, does not mention `Content-MD5` at all and so is not the document that retired it.)

## Specifications

- [RFC 9530 §2](https://www.rfc-editor.org/rfc/rfc9530.html#section-2): `Content-Digest`, the field to keep — defined for both requests and responses, which is why both are checked. Note it does not mention `Content-MD5`, so it is not what retired it
- [RFC 7231 §Appendix B](https://www.rfc-editor.org/rfc/rfc7231.html#appendix-B): Where `Content-MD5` was removed from HTTP, and the reason: inconsistent implementation with respect to partial responses
- [RFC 2616 §14.15](https://www.rfc-editor.org/rfc/rfc2616.html#section-14.15): `Content-MD5`, where it was defined — and from where RFC 7231 removed it. This reference said RFC 7231 §3.3.2, a section that does not exist in RFC 7231

## Configuration

```toml
[rules.content_md5_vs_digest_preference]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Content-Digest: sha-256=:dGVzdA==:
```

### ❌ Bad

```http
Content-Digest: sha-256=:dGVzdA==:
Content-MD5: dGVzdA==
```
