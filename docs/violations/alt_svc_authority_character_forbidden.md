<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# alt_svc_authority_character_forbidden

Alt-Svc alt-authority holds an octet no production of it admits

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 7838 §8](https://www.rfc-editor.org/rfc/rfc7838.html#section-8): Internationalization Considerations: an internationalized domain name in this field is written as A-labels, which is what makes an octet at or above %x80 inside an `alt-authority` a defect with a remedy rather than only an octet no production admits

## Configuration

```toml
[violations.alt_svc_authority_character_forbidden]
# Alt-Svc alt-authority holds an octet no production of it admits
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [alt_svc_header_syntax](../rules/alt_svc_header_syntax.md)
