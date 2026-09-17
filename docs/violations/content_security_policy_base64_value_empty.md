<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_security_policy_base64_value_empty

A nonce or hash source names no value

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [CSP3 §2.3.1](https://www.w3.org/TR/CSP3/#framework-directive-source-list): Source Lists: `source-expression`, the `nonce-source` and `hash-source` productions whose single quotes are written *inside* them, and the `base64-value` both of them carry

## Configuration

```toml
[violations.content_security_policy_base64_value_empty]
# A nonce or hash source names no value
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [content_security_policy_valid](../rules/content_security_policy_valid.md)
