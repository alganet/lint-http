<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cookie_same_site_ignored

A cookie is sent in a context its SameSite excludes

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Specifications

- [draft-ietf-httpbis-rfc6265bis](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis): `SameSite` value grammar and the `SameSite=None` requires `Secure` rule. No section: a draft renumbers between revisions

## Configuration

```toml
[violations.cookie_same_site_ignored]
# A cookie is sent in a context its SameSite excludes
severity = "info"
```

## Reported By

- [cookie_same_site_enforced](../rules/cookie_same_site_enforced.md)
