<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_accept_header_media_type_syntax

## Description

Validate `Accept` header media-range syntax. Each member must be a valid media-range (`type/subtype`, `type/*`, or `*/*`), and parameters must be well-formed (`name=value`). The `q` parameter must be a valid quality value (0.000–1.000 with up to three decimal places). This rule is conservative and focuses on syntactic correctness rather than semantic content negotiation.

## Specifications

- [RFC 9110 §7.2.1](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.2.1) — Accept header field and media-range syntax

## Configuration

Minimal example to enable the rule in `config.toml`:

```toml
[rules.message_accept_header_media_type_syntax]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Accept: text/html
Accept: application/json; charset=utf-8
Accept: text/*;q=0.8, application/json;q=0.9
Accept: */*;q=0.1
```

### ❌ Bad

```http
Accept: *
Accept: text; q=0.8
Accept: text/html; q=1.0000
Accept: application/json; charset=bad\x01
```
