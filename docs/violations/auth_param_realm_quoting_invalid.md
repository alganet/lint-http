<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# auth_param_realm_quoting_invalid

A realm is written in the syntax its section refuses

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §11.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-11.5): Establishing a Protection Space (Realm) — a realm names one protection space, each with its own authentication scheme, and a response may carry several challenges of one scheme with different realms; the section closes by admitting one spelling of the value

## Configuration

```toml
[violations.auth_param_realm_quoting_invalid]
# A realm is written in the syntax its section refuses
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [authorization_credentials_valid](../rules/authorization_credentials_valid.md)
- [proxy_authenticate_challenge_syntax](../rules/proxy_authenticate_challenge_syntax.md)
- [www_authenticate_challenge_syntax](../rules/www_authenticate_challenge_syntax.md)
