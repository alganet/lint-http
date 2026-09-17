<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# credentials_empty

Credentials are empty

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §11.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.6.2): Authorization — the field's value *consists of* credentials, which is stricter than § 11.4's optional second half

## Configuration

```toml
[violations.credentials_empty]
# Credentials are empty
severity = "warn"
```

## Reported By

- [authorization_credentials_valid](../rules/authorization_credentials_valid.md)
