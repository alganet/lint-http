<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# cookie_same_site_missing

Set-Cookie SameSite attribute carries no value

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`SHOULD`** binding the sender of the message — advice the specification gives in its own voice and the sender declined — so a finding here reports at `warn` by default.

## Specifications

- [draft-ietf-httpbis-rfc6265bis](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis): `SameSite` value grammar and the `SameSite=None` requires `Secure` rule. No section: a draft renumbers between revisions

## Configuration

```toml
[violations.cookie_same_site_missing]
# Set-Cookie SameSite attribute carries no value
# SHOULD obliges the sender, so this defaults to warn.
severity = "warn"
```

## Reported By

- [cookie_attribute_consistent](../rules/cookie_attribute_consistent.md)
