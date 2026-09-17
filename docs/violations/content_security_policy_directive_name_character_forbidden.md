<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_security_policy_directive_name_character_forbidden

A CSP directive name holds a character the production does not admit

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [CSP3 §2.3](https://www.w3.org/TR/CSP3/#framework-directives): Directives: `directive-name = 1*( ALPHA / DIGIT / "-" )`, letters, digits and a hyphen and nothing else — where an HTTP `token` also admits `_`, `.` and a dozen other marks

## Configuration

```toml
[violations.content_security_policy_directive_name_character_forbidden]
# A CSP directive name holds a character the production does not admit
severity = "warn"
```

## Reported By

- [content_security_policy_valid](../rules/content_security_policy_valid.md)
