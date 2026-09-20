<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# content_security_policy_report_to_malformed

A report-to directive names no endpoint group, so violation reports go nowhere

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [CSP3 §6.5.2](https://www.w3.org/TR/CSP3/#directive-report-to): `report-to` — `directive-value = token`, one token naming a reporting endpoint group declared elsewhere in the response, where the deprecated `report-uri` takes URI-references instead
- [CSP3 §2.2.1](https://www.w3.org/TR/CSP3/#parse-serialized-policy): Parse a serialized CSP — a directive value is the token split on ASCII whitespace, directive names are case-insensitive, and a name already in the directive set makes the later occurrence be skipped

## Configuration

```toml
[violations.content_security_policy_report_to_malformed]
# A report-to directive names no endpoint group, so violation reports go nowhere
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [content_security_policy_report_to_named](../rules/content_security_policy_report_to_named.md)
