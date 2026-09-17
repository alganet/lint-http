<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cache_control_no_cache_argument_empty

Cache-Control no-cache is qualified by no field name

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9111 §5.2.2.4](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.4): no-cache — the unqualified form's prohibition on reuse without forwarding for validation, the argument syntax `#field-name`, the qualified form defined as an argument listing one or more field names, and the Note that caches often handle it as an unqualified no-cache

## Configuration

```toml
[violations.cache_control_no_cache_argument_empty]
# Cache-Control no-cache is qualified by no field name
severity = "info"
```

## Reported By

- [cache_control_directive_valid](../rules/cache_control_directive_valid.md)
