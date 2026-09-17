<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# request_target_malformed

A request-target derives from none of the four forms

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-2.2): Conformance — a sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules

## Configuration

```toml
[violations.request_target_malformed]
# A request-target derives from none of the four forms
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [request_target_form_valid](../rules/request_target_form_valid.md)
