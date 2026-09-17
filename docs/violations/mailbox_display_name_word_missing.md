<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# mailbox_display_name_word_missing

Mailbox display-name holds no word

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**A value that does not derive from the ABNF production it cites.** The production states no keyword; what obliges it is RFC 9110 §2.2 — "A sender MUST NOT generate protocol elements that do not match the grammar defined by the corresponding ABNF rules" — which binds the sender, so a finding here reports at `error` by default.

## Specifications

- [RFC 5322 §3.2.5](https://www.rfc-editor.org/rfc/rfc5322.html#section-3.2.5): `phrase = 1*word` — a display-name holds at least one atom or quoted-string, and `obs-phrase`'s bare `.` is not one

## Configuration

```toml
[violations.mailbox_display_name_word_missing]
# Mailbox display-name holds no word
# GRAMMAR obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [from_header_email_syntax](../rules/from_header_email_syntax.md)
