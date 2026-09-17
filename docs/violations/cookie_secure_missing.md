<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cookie_secure_missing

A SameSite=None cookie is not Secure

## Message

Set-Cookie with 'SameSite=None' must also set 'Secure'

## Specifications

- [draft-ietf-httpbis-rfc6265bis](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis): `SameSite` value grammar and the `SameSite=None` requires `Secure` rule. No section: a draft renumbers between revisions

## Configuration

```toml
[violations.cookie_secure_missing]
# A SameSite=None cookie is not Secure
severity = "error"
```

## Reported By

- [cookie_attribute_consistent](../rules/cookie_attribute_consistent.md)
