<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# charset_unregistered

Charset name is not one the deployment recognises

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §8.3.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-8.3.2): Charset: what the parameter means, that names are matched case-insensitively, and the "ought to be registered" guidance that motivates this rule — guidance, not a requirement, and not something this rule verifies

## Configuration

```toml
[violations.charset_unregistered]
# Charset name is not one the deployment recognises
severity = "warn"
```

## Reported By

- [charset_registered](../rules/charset_registered.md)
