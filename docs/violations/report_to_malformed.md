<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# report_to_malformed

Report-To does not parse, so none of the endpoint groups it declares exist

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [MDN Report-To](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Report-To): Report-To — a response header marked Deprecated and Non-standard, replaced by `Reporting-Endpoints`, whose value is one or more endpoint-group definitions written as a JSON array with the surrounding brackets omitted
- [draft-reschke-http-jfv-07 §2](https://datatracker.ietf.org/doc/html/draft-reschke-http-jfv-07#section-2): Syntax — `json-field-value = #json-field-item`, the comma-separated list of JSON texts that a field deferring to this draft carries
- [draft-reschke-http-jfv-07 §4](https://datatracker.ietf.org/doc/html/draft-reschke-http-jfv-07#section-4): Recipient Requirements — combine the field lines, add a leading "[" and a trailing "]", run a JSON parser; pinned to -07 because the unversioned draft is now a stub with no § 4 in it

## Configuration

```toml
[violations.report_to_malformed]
# Report-To does not parse, so none of the endpoint groups it declares exist
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [report_to_groups_valid](../rules/report_to_groups_valid.md)
