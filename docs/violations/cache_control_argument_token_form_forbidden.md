<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cache_control_argument_token_form_forbidden

A Cache-Control field-name argument is written in the token form

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`SHOULD`** binding the sender of the message — advice the specification gives in its own voice and the sender declined — so a finding here reports at `warn` by default.

## Specifications

- [RFC 9111 §5.2.2.4](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.4): no-cache — the unqualified form's prohibition on reuse without forwarding for validation, the argument syntax `#field-name`, the qualified form defined as an argument listing one or more field names, and the Note that caches often handle it as an unqualified no-cache
- [RFC 9111 §5.2.2.7](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2.2.7): private — the unqualified form's prohibition on a shared cache storing the response at all, the argument syntax `#field-name`, the qualified form defined as an argument listing one or more field names, and the Note that caches often handle it as an unqualified private

## Configuration

```toml
[violations.cache_control_argument_token_form_forbidden]
# A Cache-Control field-name argument is written in the token form
# SHOULD obliges the sender, so this defaults to warn.
severity = "warn"
```

## Reported By

- [cache_control_directive_valid](../rules/cache_control_directive_valid.md)
