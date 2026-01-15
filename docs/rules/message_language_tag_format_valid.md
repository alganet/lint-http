<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# message_language_tag_format_valid

## Description

Validate that any language tag appearing in HTTP headers such as `Content-Language` and `Accept-Language` follows a well-formed BCP 47-style syntax (RFC 5646). This check is conservative: it rejects obvious syntax problems (invalid characters, empty subtags, consecutive hyphens, or overly long subtags) while accepting common valid forms such as `en`, `en-US`, `zh-Hant`, `sr-Latn-RS`, and private-use tags like `x-custom`.

## Specifications

- [RFC 5646 — BCP 47 language tag syntax](https://www.rfc-editor.org/rfc/rfc5646.html)
- [RFC 9110 §7.2.5 — Accept-Language](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.2.5) — Accept-Language uses language-tags from RFC 5646.
- [RFC 9110 §7.3.5 — Content-Language](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.3.5) — Content-Language uses language-tags from RFC 5646.

## Configuration

TOML example to enable the rule:

```toml
[rules.message_language_tag_format_valid]
enabled = true
severity = "warn"
```

## Examples

✅ Good

```http
Accept-Language: en, fr-CA;q=0.8
Content-Language: en-US
```

❌ Bad

```http
Accept-Language: en_US
Content-Language: en-TooLongSubtag123
```