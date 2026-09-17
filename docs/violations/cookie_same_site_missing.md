<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cookie_same_site_missing

Set-Cookie SameSite attribute carries no value

## Message

Set-Cookie attribute 'SameSite' requires a value

## Specifications

- [draft-ietf-httpbis-rfc6265bis](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis): `SameSite` value grammar and the `SameSite=None` requires `Secure` rule. No section: a draft renumbers between revisions

## Configuration

```toml
[violations.cookie_same_site_missing]
# Set-Cookie SameSite attribute carries no value
severity = "warn"
```

## Reported By

- [cookie_attribute_consistent](../rules/cookie_attribute_consistent.md)
