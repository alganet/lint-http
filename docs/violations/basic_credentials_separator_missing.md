<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# basic_credentials_separator_missing

Basic credentials hold no ':' separator

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

**No sentence obliges the sender of this message.** Either nothing states a requirement about this defect, or the keyword in the text it cites binds the *recipient* and so says nothing about the peer being reported. The severity below is a judgement, argued in the catalogue entry.

## Specifications

- [RFC 7617 §2](https://www.rfc-editor.org/rfc/rfc7617.html#section-2): The 'Basic' Authentication Scheme — `user-pass = userid ":" password`, base64-encoded, with control characters forbidden in either half

## Configuration

```toml
[violations.basic_credentials_separator_missing]
# Basic credentials hold no ':' separator
severity = "warn"
```

## Reported By

- [basic_auth_base64_valid](../rules/basic_auth_base64_valid.md)
