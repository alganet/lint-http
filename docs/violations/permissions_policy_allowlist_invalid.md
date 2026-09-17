<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# permissions_policy_allowlist_invalid

A directive's allowlist is none of the permitted forms

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [Permissions Policy](https://w3c.github.io/webappsec-permissions-policy/#structured-header-serialization): §5.2 Structured header serialization — the production this subject answers for. Not §5.1, which is the HTML attribute and has a feature-identifier grammar of its own

## Configuration

```toml
[violations.permissions_policy_allowlist_invalid]
# A directive's allowlist is none of the permitted forms
severity = "warn"
```

## Reported By

- [permissions_policy_directives_valid](../rules/permissions_policy_directives_valid.md)
