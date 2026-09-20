<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cache_control_directive_value_empty

Cache-Control directive writes an '=' and no value after it

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 9111 §5.2](https://www.rfc-editor.org/rfc/rfc9111.html#section-5.2): Cache-Control directives and general directive syntax — `cache-directive = token [ "=" ( token / quoted-string ) ]`, the production an argument's presence and form derive from

## Configuration

```toml
[violations.cache_control_directive_value_empty]
# Cache-Control directive writes an '=' and no value after it
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [cache_control_token_valid](../rules/cache_control_token_valid.md)
