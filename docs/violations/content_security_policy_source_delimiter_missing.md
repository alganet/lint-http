<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_security_policy_source_delimiter_missing

A nonce or hash source is written without its single quotes

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [CSP3 §2.3.1](https://www.w3.org/TR/CSP3/#framework-directive-source-list): Source Lists: `source-expression`, the `nonce-source` and `hash-source` productions whose single quotes are written *inside* them, and the `base64-value` both of them carry

## Configuration

```toml
[violations.content_security_policy_source_delimiter_missing]
# A nonce or hash source is written without its single quotes
severity = "warn"
```

## Reported By

- [content_security_policy_valid](../rules/content_security_policy_valid.md)
