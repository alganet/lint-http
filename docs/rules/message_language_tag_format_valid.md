<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# Message Language Tag Format Valid

## Description

Validate that any language tag appearing in HTTP headers such as `Content-Language` and `Accept-Language` follows a well-formed BCP 47-style syntax (RFC 5646). This check is conservative: it rejects obvious syntax problems (invalid characters, empty subtags, consecutive hyphens, or overly long subtags) while accepting common valid forms such as `en`, `en-US`, `zh-Hant`, `sr-Latn-RS`, and private-use tags like `x-custom`.

## Specifications

- [RFC 5646](https://www.rfc-editor.org/rfc/rfc5646.html): BCP 47 language tag syntax
- [RFC 9110 §12.5.4](https://www.rfc-editor.org/rfc/rfc9110.html#section-12.5.4): Accept-Language — Accept-Language uses language-tags from RFC 5646
- [RFC 9110 §8.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.5): Content-Language — Content-Language uses language-tags from RFC 5646

## Configuration

```toml
[rules.message_language_tag_format_valid]
enabled = true
severity = "warn"
```

## Examples

### ✅ Good

```http
Accept-Language: en, fr-CA;q=0.8
Content-Language: en-US
```

### ❌ Bad

```http
Accept-Language: en_US
Content-Language: en-TooLongSubtag123
```
