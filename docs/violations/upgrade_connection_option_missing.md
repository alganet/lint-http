<!--
SPDX-FileCopyrightText: 2026 Alexandre Gomes Gaigalas <alganet@gmail.com>

SPDX-License-Identifier: ISC
-->

# upgrade_connection_option_missing

Upgrade is sent with no upgrade connection-option in Connection

## Message

_Written where it is reported: this defect's message names the value that caused it, so it is not fixed text._

## Obligation

A **`MUST`** binding the sender of the message, so a finding here reports at `error` by default.

## Specifications

- [RFC 9110 §7.8](https://www.rfc-editor.org/rfc/rfc9110.html#section-7.8): Upgrade — the sender's obligation to name the field as a connection-option beside it, and the `#protocol` grammar that makes the field's presence the thing the obligation turns on

## Configuration

```toml
[violations.upgrade_connection_option_missing]
# Upgrade is sent with no upgrade connection-option in Connection
# MUST obliges the sender, so this defaults to error.
severity = "error"
```

## Reported By

- [sec_websocket_headers_consistent](../rules/sec_websocket_headers_consistent.md)
- [upgrade_and_connection_consistent](../rules/upgrade_and_connection_consistent.md)
