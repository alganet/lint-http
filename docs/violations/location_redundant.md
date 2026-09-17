<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# location_redundant

Location is sent on a status that gives it no referent

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 9110 §10.2.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.2): `Location = URI-reference`; the value's referent is defined for 201 (Created) and for 3xx (Redirection) responses, and for no other status

## Configuration

```toml
[violations.location_redundant]
# Location is sent on a status that gives it no referent
severity = "info"
```

## Reported By

- [redirect_status_and_location_valid](../rules/redirect_status_and_location_valid.md)
