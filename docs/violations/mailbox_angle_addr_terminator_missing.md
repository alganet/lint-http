<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# mailbox_angle_addr_terminator_missing

Mailbox angle-addr is never closed

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 5322 §3.4](https://www.rfc-editor.org/rfc/rfc5322.html#section-3.4): `mailbox = name-addr / addr-spec`, `angle-addr` beside it, and `mailbox-list` — the neighbouring production a top-level comma derives from

## Configuration

```toml
[violations.mailbox_angle_addr_terminator_missing]
# Mailbox angle-addr is never closed
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [from_header_email_syntax](../rules/from_header_email_syntax.md)
