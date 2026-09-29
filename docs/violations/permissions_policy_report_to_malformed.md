<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# permissions_policy_report_to_malformed

A directive's report-to parameter is not a Token

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No one sentence sets this level.** Nothing states a requirement about this defect; or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported; or the message cannot show that its sender is the party the keyword binds; or the defect is reported in two places that two sentences of different strength govern, and one level has to answer for both. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [Permissions Policy](https://w3c.github.io/webappsec-permissions-policy/#structured-header-serialization): §5.2 Structured header serialization — the production this subject answers for. Not §5.1, which is the HTML attribute and has a feature-identifier grammar of its own

## Configuration

```toml
[violations.permissions_policy_report_to_malformed]
# A directive's report-to parameter is not a Token
severity = "info"
```

## Reported By

- [permissions_policy_directives_valid](../rules/permissions_policy_directives_valid.md)
