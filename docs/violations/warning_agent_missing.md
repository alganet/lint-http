<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# warning_agent_missing

Warning member names no warn-agent

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 7234 §5.5](https://www.rfc-editor.org/rfc/rfc7234.html#section-5.5): The last statement of the `Warning` grammar, and the requirements about warn-codes and warn-dates that go with it. Obsoleted by RFC 9111, which removed the field rather than restating it — so this is where the productions are read from, and RFC 9111 §5.5 is where the field's status is read from

## Configuration

```toml
[violations.warning_agent_missing]
# Warning member names no warn-agent
severity = "warn"
```

## Reported By

- [warning_header_syntax](../rules/warning_header_syntax.md)
