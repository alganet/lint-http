<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# referer_userinfo_forbidden

A Referer carries the deprecated userinfo subcomponent

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §10.1.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.1.3): Referer — the field's grammar, the fragment and userinfo MUST NOT, the unsecured-request MUST NOT, and the two declined conditionals

## Configuration

```toml
[violations.referer_userinfo_forbidden]
# A Referer carries the deprecated userinfo subcomponent
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [referer_uri_valid](../rules/referer_uri_valid.md)
