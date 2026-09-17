<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# alt_svc_parameter_value_empty

Alt-Svc parameter is written with no value after its '='

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 7838 §3](https://www.rfc-editor.org/rfc/rfc7838.html#section-3): The Alt-Svc HTTP Header Field: `Alt-Svc = clear / 1#alt-value` and the productions under it, the case-sensitive `clear` keyword, the three percent-encoding constraints on a `protocol-id`, and the prose requiring a colon and a port inside the `alt-authority`

## Configuration

```toml
[violations.alt_svc_parameter_value_empty]
# Alt-Svc parameter is written with no value after its '='
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [alt_svc_header_syntax](../rules/alt_svc_header_syntax.md)
