<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_security_policy_directive_empty

A policy opens with a semicolon and names no first directive

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [CSP3 §2.2](https://www.w3.org/TR/CSP3/#framework-policy): Policies: `serialized-policy = serialized-directive *( optional-ascii-whitespace ";" [ optional-ascii-whitespace serialized-directive ] )` — one unbracketed directive and any number of bracketed ones, which is what decides whether a given `;` names anything

## Configuration

```toml
[violations.content_security_policy_directive_empty]
# A policy opens with a semicolon and names no first directive
severity = "info"
```

## Reported By

- [content_security_policy_valid](../rules/content_security_policy_valid.md)
