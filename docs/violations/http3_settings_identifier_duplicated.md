<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# http3_settings_identifier_duplicated

One SETTINGS frame states the same identifier twice

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9114 §7.2.4](https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4): SETTINGS — the frame each peer sends first on its control stream and never again, and the prohibition on one identifier occurring twice inside it

## Configuration

```toml
[violations.http3_settings_identifier_duplicated]
# One SETTINGS frame states the same identifier twice
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [http3_settings_frame](../rules/http3_settings_frame.md)
