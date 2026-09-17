<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# retry_after_malformed

A Retry-After is neither a date nor a delay

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §10.2.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.3): Defines Retry-After generally, with no condition on the status code, then says what it indicates on a 503 and on any 3xx

## Configuration

```toml
[violations.retry_after_malformed]
# A Retry-After is neither a date nor a delay
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [retry_after_date_or_delay](../rules/retry_after_date_or_delay.md)
