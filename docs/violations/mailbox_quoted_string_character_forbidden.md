<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# mailbox_quoted_string_character_forbidden

Mailbox quoted-string holds a character outside qtext

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 5322 §3.2.4](https://www.rfc-editor.org/rfc/rfc5322.html#section-3.2.4): `quoted-string` and `qtext` — the quoted alternative, and the class it admits between the two DQUOTEs

## Configuration

```toml
[violations.mailbox_quoted_string_character_forbidden]
# Mailbox quoted-string holds a character outside qtext
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [from_header_email_syntax](../rules/from_header_email_syntax.md)
