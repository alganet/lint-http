<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_security_policy_base64_value_malformed

A nonce value holds a character base64-value does not admit

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [CSP3 §2.3.1](https://www.w3.org/TR/CSP3/#framework-directive-source-list): Source Lists: `source-expression`, the `nonce-source` and `hash-source` productions whose single quotes are written *inside* them, and the `base64-value` both of them carry

## Configuration

```toml
[violations.content_security_policy_base64_value_malformed]
# A nonce value holds a character base64-value does not admit
severity = "warn"
```

## Reported By

- [content_security_policy_valid](../rules/content_security_policy_valid.md)
