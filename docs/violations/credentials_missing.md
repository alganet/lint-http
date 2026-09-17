<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# credentials_missing

Credentials are absent after the scheme

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [RFC 9110 §11.6.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.6.2): Authorization — the field's value *consists of* credentials, which is stricter than § 11.4's optional second half

## Configuration

```toml
[violations.credentials_missing]
# Credentials are absent after the scheme
severity = "warn"
```

## Reported By

- [authorization_credentials_valid](../rules/authorization_credentials_valid.md)
- [basic_auth_base64_valid](../rules/basic_auth_base64_valid.md)
- [bearer_token_syntax](../rules/bearer_token_syntax.md)
