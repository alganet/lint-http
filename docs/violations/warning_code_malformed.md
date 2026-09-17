<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# warning_code_malformed

Warning member's warn-code is not three digits

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 7234 §5.5](https://www.rfc-editor.org/rfc/rfc7234.html#section-5.5): The last statement of the `Warning` grammar, and the requirements about warn-codes and warn-dates that go with it. Obsoleted by RFC 9111, which removed the field rather than restating it — so this is where the productions are read from, and RFC 9111 §5.5 is where the field's status is read from

## Configuration

```toml
[violations.warning_code_malformed]
# Warning member's warn-code is not three digits
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [warning_header_syntax](../rules/warning_header_syntax.md)
